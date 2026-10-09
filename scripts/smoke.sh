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
printf '{}\n' > "$fixture/repo/web/package-lock.json"
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
expect "files recognised" "$(echo "$report" | field 'sorted(f["kind"] for f in d["files"])')" "['dockerfile', 'npm-lock', 'pyproject']"
expect "link recorded" "$(echo "$report" | field 'd["symlinks"]')" "['linked']"
expect "link not followed" "$(echo "$report" | field '[f["path"] for f in d["files"] if "go.mod" in f["path"]]')" "[]"
expect "text report by default" "$(scan | head -1)" "vulnscan 0.1.0: /scan"
expect "nothing written into the target" "$([ "$(listing)" = "$before" ] && echo unchanged || echo changed)" "unchanged"

set +e
scan scan /nowhere > /dev/null 2>&1
code=$?
set -e
expect "a missing target exits with" "$code" "2"

echo "smoke test passed"
