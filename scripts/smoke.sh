#!/usr/bin/env bash
# Checks the image from outside: its version, that it runs unprivileged,
# a scan of a fixture repository mounted read-only with no network (JSON
# report, exit code 0), a link out of the repository recorded and not
# followed, nothing written into the target, and exit code 2 for a target
# that is not there.
set -euo pipefail
image="${1:-vulnscan:local}"

expect() { # expect NAME GOT WANT
  if [ "$2" != "$3" ]; then echo "FAIL $1: got $2, want $3" >&2; exit 1; fi
  echo "ok   $1: $2"
}

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/repo/web" "$fixture/outside"
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

scan() { docker run --rm --network none -v "$fixture/repo:/scan:ro" "$image" "$@"; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

expect "version" "$(docker run --rm --network none "$image" --version)" "0.1.0"
expect "runs as uid" "$(docker run --rm --network none --entrypoint id "$image" -u)" "10001"

report="$(scan scan /scan --format json)"
expect "scan exit code" "$?" "0"
expect "files recognised" "$(echo "$report" | field 'sorted(f["kind"] for f in d["files"])')" "['dockerfile', 'npm-lock', 'pyproject', 'requirements']"
expect "packages found" "$(echo "$report" | field 'sorted((p["name"], p.get("version"), p["how"]) for p in d["inventory"]["packages"])')" "[('django', '5.1.2', 'pinned'), ('requests', None, 'declared'), ('ws', '8.22.0', 'locked')]"
expect "link recorded" "$(echo "$report" | field 'd["symlinks"]')" "['linked']"
expect "link not followed" "$(echo "$report" | field '[f["path"] for f in d["files"] if "go.mod" in f["path"]]')" "[]"
expect "text report by default" "$(scan | head -1)" "vulnscan 0.1.0: /scan"
expect "nothing written into the target" "$([ "$(listing)" = "$before" ] && echo unchanged || echo changed)" "unchanged"

# Advisory data: indexed from a file (no network), then looked up from a
# read-only mount.
mkdir -p "$fixture/data"
chmod 777 "$fixture/data"  # writable by the container's user, on any host
python3 - "$fixture/data/PyPI.zip" <<'PY'
import json, sys, zipfile
advisory = {"id": "PYSEC-1", "modified": "2026-01-01T00:00:00Z", "summary": "a test",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "Django"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "5.1.3"}]}]}]}
with zipfile.ZipFile(sys.argv[1], "w") as zf:
    zf.writestr("PYSEC-1.json", json.dumps(advisory))
PY
data() { docker run --rm --network none -v "$fixture/data:/data$1" "$image" "${@:2}"; }
expect "update from a file" "$(data "" update --from PyPI=/data/PyPI.zip | head -1)" "PyPI: 1 advisories (0 withdrawn left out, 0 not readable); 0.0 MB, sha256 $(shasum -a 256 "$fixture/data/PyPI.zip" | cut -c1-16)..., not checked against the server"
set +e
data :ro lookup PyPI django 5.1.2 > "$fixture/lookup.txt"
code=$?
set -e
expect "lookup from a read-only mount exits with" "$code" "1"
expect "lookup names the advisory" "$(grep -c 'AFFECTED  PYSEC-1' "$fixture/lookup.txt")" "1"

set +e
scan scan /nowhere > /dev/null 2>&1
code=$?
set -e
expect "a missing target exits with" "$code" "2"

echo "smoke test passed"
