# VulnScan

A scanner for repositories I own. It reads a repository and reports what
is wrong with it from a security point of view: dependencies with known
vulnerabilities, secrets committed to it, and risky container settings.
Its first real target is my own portfolio, about 30 repositories in Python,
TypeScript and JavaScript, Go, Java and R.

> **Scope:** VulnScan reads files in repositories I own, read-only. It does
> not scan networks or send requests to other systems; its only network use
> (from Milestone 2) is downloading public advisory data from OSV. Scans run
> with no network at all.

It deliberately does not use pip-audit, safety, osv-scanner, npm audit,
govulncheck, Trivy, Grype, Snyk, gitleaks, trufflehog, detect-secrets,
hadolint or Checkov underneath: the point is to build what they do.

> **Status:** Milestone 0 of 7, the skeleton. `vulnscan scan` walks a
> repository and lists the files later milestones will read (manifests,
> lockfiles, Dockerfiles, Compose files, Python environments). It checks
> nothing yet, so it reports no findings.

## Status

| # | Milestone | Status |
|---|-----------|--------|
| 0 | Skeleton: Python 3.14 package, a `vulnscan scan PATH` CLI with text and JSON output and exit codes; ruff, mypy --strict, pytest + Hypothesis; a non-root image that scans a folder mounted read-only; CI; a smoke test | Built |
| 1 | Inventory: exactly what a repository depends on, from installed Python environments, lockfiles and manifests (Python, npm, Go) | Not started |
| 2 | Advisory data from OSV in a local index; version ordering for PEP 440, npm SemVer and Go, written by hand; OSV's affected ranges | Not started |
| 3 | Findings: packages matched to advisories, the fixing version, CVSS 3.1 scores; text, JSON and SARIF; `--fail-on`; a baseline file | Not started |
| 4 | Secrets in files and git history, never shown in a finding | Not started |
| 5 | Dockerfile and Compose rules | Not started |
| 6 | Evaluation on my own repositories: every finding labelled by hand; dependency findings cross-checked against osv-scanner | Not started |
| 7 | README: diagram, decisions, failures, results; explain-it-yourself prompts | Not started |

"Built" means built and tested on my machine; there is no GitHub repository
yet, so CI has not run.

## Quickstart

With Docker:

```bash
make image
docker run --rm --network none -v "$PWD:/scan:ro" vulnscan:local
docker run --rm --network none -v "$PWD:/scan:ro" vulnscan:local scan /scan --format json
```

Or with Python 3.14:

```bash
make install
make scan TARGET=../some-repo
```

`make smoke` builds the image and checks it from outside: it runs
unprivileged, scans a fixture repository mounted read-only with no
network, records a link out of the repository without following it, and
writes nothing into the target.

## What a scan reads

- **The target directory, and nothing outside it.** Symbolic links are
  listed, never followed: a link in a repository can point anywhere on the
  machine. Nothing is written.
- **Not:** `.git`, `node_modules`, `__pycache__` and tool caches. A Python
  virtual environment is recognised by its `pyvenv.cfg` (whatever the
  folder is called) and listed separately: its installed packages are what
  the inventory (Milestone 1) will read.
- **Recognised files,** by name: `requirements*.txt`, `pyproject.toml`,
  `uv.lock`, `poetry.lock`, `Pipfile.lock`, `package.json`,
  `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.mod`, `go.sum`,
  `pom.xml`, `build.gradle`, `renv.lock`, `Cargo.lock`, Dockerfiles and
  Compose files. Recognising a file is not reading it: which of these are
  read is decided milestone by milestone, and stated.
- **Exit codes:** 0, nothing at or above the failure threshold; 1, findings
  at or above it; 2, the scan could not be done (a missing path, a bad
  option). Unreadable directories are reported in the output, not fatal.

## Development

```bash
make install   # a .venv with the dev tools
make check     # ruff, mypy --strict, pytest (with Hypothesis)
make smoke     # the image, checked from outside
```

The tests run against `src/` (pytest's `pythonpath`), and `make scan` uses
`PYTHONPATH=src`: in this iCloud-synced folder macOS hides everything in
`.venv`, and Python 3.13+ skips hidden `.pth` files, so the editable
install does not work outside pytest.

## Layout

| Path | What |
|------|------|
| `src/vulnscan/cli.py` | The command line, and its exit codes |
| `src/vulnscan/walk.py` | Which files a scan reads: no links followed, nothing written |
| `src/vulnscan/classify.py` | Which files matter, by name |
| `src/vulnscan/report.py` | The report, as JSON (with a schema number) and as text |
| `tests/` | The walker (including random trees with Hypothesis), the classifier, the CLI |
| `scripts/smoke.sh` | Checks the image from outside |
