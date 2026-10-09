#!/usr/bin/env bash
# Checks the image from outside, as a user runs it: its version, that it
# runs unprivileged; advisory data indexed from a file (no network); then a
# scan of a fixture repository mounted read-only, with the data mounted
# read-only and no network: the inventory, a finding with its fix, exit
# code 1, valid-looking SARIF, an accepted finding passing, a link out of
# the repository recorded and not followed, nothing written into the
# target; a scan without data refusing to pass; and exit code 2 for a
# target that is not there.
set -euo pipefail
image="${1:-vulnscan:local}"

expect() { # expect NAME GOT WANT
  if [ "$2" != "$3" ]; then echo "FAIL $1: got $2, want $3" >&2; exit 1; fi
  echo "ok   $1: $2"
}

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/repo/web" "$fixture/outside" "$fixture/data"
chmod 777 "$fixture/data"  # writable by the container's user, on any host
printf '[project]\nname = "fixture"\n' > "$fixture/repo/pyproject.toml"
cat > "$fixture/repo/web/package-lock.json" <<'JSON'
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "web", "dependencies": {"ws": "^8.0.0"}},
    "node_modules/ws": {"version": "8.22.0"}
  }
}
JSON
printf 'Django==5.1.2\nrequests>=2.31\n' > "$fixture/repo/requirements.txt"
printf 'FROM python:3.14-slim\n' > "$fixture/repo/Dockerfile"
printf 'module example.com/x\n' > "$fixture/outside/go.mod"
ln -s ../outside "$fixture/repo/linked"
listing() { (cd "$fixture/repo" && ls -laR | shasum); }
before="$(listing)"

# One advisory: Django before 5.1.3.
python3 - "$fixture/data" <<'PY'
import json, sys, zipfile
advisory = {"id": "PYSEC-1", "modified": "2026-01-01T00:00:00Z", "summary": "a test",
            "aliases": ["CVE-2026-0001"],
            "severity": [{"type": "CVSS_V3",
                          "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
            "affected": [{"package": {"ecosystem": "PyPI", "name": "Django"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "5.1.3"}]}]}]}
for ecosystem, entries in (("PyPI", [advisory]), ("npm", []), ("Go", [])):
    with zipfile.ZipFile(f"{sys.argv[1]}/{ecosystem}.zip", "w") as zf:
        for a in entries:
            zf.writestr(f"{a['id']}.json", json.dumps(a))
PY

run() { docker run --rm --network none "$@"; }
data() { run -v "$fixture/data:/data$1" "$image" "${@:2}"; }
scan() { run -v "$fixture/repo:/scan:ro" -v "$fixture/data:/data:ro" "$image" "$@"; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

expect "version" "$(run "$image" --version)" "0.1.0"
expect "runs as uid" "$(run --entrypoint id "$image" -u)" "10001"
for ecosystem in PyPI npm Go; do
  data "" update --from "$ecosystem=/data/$ecosystem.zip" > /dev/null
done
expect "advisory data indexed from files" "$(data :ro lookup PyPI django 5.1.2 | tail -1)" "1 affecting it"

set +e
report="$(scan scan /scan --format json)"
code=$?
set -e
expect "scan exit code (a finding)" "$code" "1"
expect "files recognised" "$(echo "$report" | field 'sorted(f["kind"] for f in d["files"])')" "['dockerfile', 'npm-lock', 'pyproject', 'requirements']"
expect "packages found" "$(echo "$report" | field 'sorted((p["name"], p.get("version"), p["how"]) for p in d["inventory"]["packages"])')" "[('django', '5.1.2', 'pinned'), ('requests', None, 'declared'), ('ws', '8.22.0', 'locked')]"
expect "the finding" "$(echo "$report" | field '[(f["severity"], f["score"], f["package"]["name"], f["advisories"][0], f["fixed_in"]) for f in d["findings"]]')" "[('high', 7.5, 'django', 'PYSEC-1', '5.1.3')]"
expect "link recorded" "$(echo "$report" | field 'd["symlinks"]')" "['linked']"
expect "link not followed" "$(echo "$report" | field '[f["path"] for f in d["files"] if "go.mod" in f["path"]]')" "[]"
set +e
sarif="$(scan scan /scan --format sarif)"
set -e
expect "SARIF result" "$(echo "$sarif" | field 'd["version"], d["runs"][0]["results"][0]["ruleId"], d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]')" "2.1.0 PYSEC-1 1"
expect "--fail-on critical passes it" "$(scan scan /scan --fail-on critical > /dev/null; echo $?)" "0"

# (Checked before this script itself writes into the fixture, below.)
expect "nothing written into the target" "$([ "$(listing)" = "$before" ] && echo unchanged || echo changed)" "unchanged"

# Accepted, in the repository's own .vulnscan.toml.
printf '[[accept]]\nadvisory = "CVE-2026-0001"\nreason = "fixture"\nexpires = 2099-01-01\n' > "$fixture/repo/.vulnscan.toml"
expect "an accepted finding passes" "$(scan scan /scan > /dev/null; echo $?)" "0"
rm "$fixture/repo/.vulnscan.toml"

set +e
run -v "$fixture/repo:/scan:ro" "$image" scan /scan > /dev/null 2>&1
code=$?
set -e
expect "with no advisory data, a scan exits with" "$code" "2"
expect "the inventory alone, on purpose" "$(run -v "$fixture/repo:/scan:ro" "$image" scan /scan --no-advisories > /dev/null; echo $?)" "0"

set +e
scan scan /nowhere > /dev/null 2>&1
code=$?
set -e
expect "a missing target exits with" "$code" "2"

echo "smoke test passed"
