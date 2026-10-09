#!/usr/bin/env bash
# Checks the image from outside, as a user runs it: its version, that it
# runs unprivileged; advisory data indexed from a file (no network); then a
# scan of a fixture repository mounted read-only, with the data mounted
# read-only and no network: the inventory, a finding with its fix, exit
# code 1, valid-looking SARIF, an accepted finding passing, a link out of
# the repository recorded and not followed, nothing written into the
# target; a scan without data refusing to pass; and exit code 2 for a
# target that is not there. Then secrets: a git repository (made on the
# host, owned by another user than the container's, with no git in the
# image) whose fake secrets are found in HEAD, in history and in an
# ignored file, and never printed in any format. Then a Dockerfile and a
# Compose file with risky settings: each rule found, no password printed.
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
# Pinned and unprivileged: the container rules have nothing to say here.
printf 'FROM python:3.14-slim@sha256:%s\nUSER 10001\n' "$(printf 'a%.0s' $(seq 64))" > "$fixture/repo/Dockerfile"
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

# Secrets: fake tokens made here, at random, so that no file holds one.
secrets="$fixture/secrets"
mkdir -p "$secrets"
token() { python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('gh'+'p_'+''.join(secrets.choice(a) for _ in range(36)))"; }
kept="$(token)"; removed="$(token)"; ignored="$(token)"
g() { git -C "$secrets" -c user.name=smoke -c user.email=smoke@example.invalid -c commit.gpgsign=false "$@"; }
g init -q -b main
printf '.env\n' > "$secrets/.gitignore"
printf 'TOKEN = "%s"\n' "$kept" > "$secrets/app.py"
printf 'TOKEN = "%s"\n' "$removed" > "$secrets/old.py"
g add -A && g commit -q -m first
g rm -q old.py && g commit -q -m "remove old.py"
printf 'TOKEN=%s\n' "$ignored" > "$secrets/.env"
secrets_listing() { (cd "$secrets" && ls -laR | shasum); }
secrets_before="$(secrets_listing)"
sscan() { run -v "$secrets:/scan:ro" "$image" scan /scan --no-advisories "$@"; }

set +e
report="$(sscan --format json 2>&1)"
code=$?
text="$(sscan 2>&1)"
sarif="$(sscan --format sarif 2>&1)"
set -e
expect "secrets: exit code" "$code" "1"
expect "secrets: where each is" "$(echo "$report" | field 'sorted((f["path"], f["rule"], f["state"]) for f in d["secrets"]["findings"])')" "[('.env', 'github-token', 'uncommitted'), ('app.py', 'github-token', 'committed'), ('old.py', 'github-token', 'history')]"
expect "secrets: history read without git" "$(echo "$report" | field 'd["secrets"]["repositories"][0]["commits"], d["secrets"]["repositories"][0]["error"]')" "2 None"
for value in "$kept" "$removed" "$ignored"; do
  random_part="${value:4}"
  for output in "$report" "$text" "$sarif"; do
    case "$output" in *"$random_part"*|*"${random_part:0:12}"*) echo "FAIL a secret was printed" >&2; exit 1;; esac
  done
done
echo "ok   secrets: none of the three printed, in text, JSON or SARIF"
expect "secrets: nothing written into the repository" "$([ "$(secrets_listing)" = "$secrets_before" ] && echo unchanged || echo changed)" "unchanged"

# Container rules.
boxes="$fixture/containers"
mkdir -p "$boxes"
cat > "$boxes/Dockerfile" <<'DOCKERFILE'
FROM python:3.14-slim
ADD https://example.com/tool.tar.gz /opt/
RUN curl -fsSL https://example.com/install.sh | sh
ENV DB_PASSWORD=smokepass77
EXPOSE 8000
DOCKERFILE
cat > "$boxes/compose.yaml" <<'COMPOSE'
services:
  db:
    image: postgres:17
    ports: ["5432:5432"]
    environment:
      POSTGRES_USER: smokeuser77
      POSTGRES_PASSWORD: smokeuser77
  agent:
    image: busybox:1.37
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
COMPOSE
set +e
report="$(run -v "$boxes:/scan:ro" "$image" scan /scan --no-advisories --format json 2>&1)"
code=$?
set -e
expect "containers: exit code" "$code" "1"
expect "containers: rules found" "$(echo "$report" | field 'sorted({f["rule"] for f in d["containers"]["findings"]})')" "['compose/database-port-published', 'compose/default-password', 'compose/docker-socket', 'compose/privileged', 'dockerfile/add-from-url', 'dockerfile/base-image-no-digest', 'dockerfile/no-healthcheck', 'dockerfile/pipe-to-shell', 'dockerfile/runs-as-root', 'dockerfile/secret-in-env']"
case "$report" in *smokepass77*|*smokeuser77*) echo "FAIL a password was printed" >&2; exit 1;; esac
echo "ok   containers: no password printed"

echo "smoke test passed"
