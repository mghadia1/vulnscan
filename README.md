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

> **Status:** Milestones 0-1 of 7. `vulnscan scan` walks a repository and
> builds its inventory: every Python, npm and Go package it depends on,
> with the version and how sure that version is (installed, locked, pinned
> or only declared). It checks nothing against advisories yet, so it
> reports no findings.

## Status

| # | Milestone | Status |
|---|-----------|--------|
| 0 | Skeleton: Python 3.14 package, a `vulnscan scan PATH` CLI with text and JSON output and exit codes; ruff, mypy --strict, pytest + Hypothesis; a non-root image that scans a folder mounted read-only; CI; a smoke test | Built |
| 1 | Inventory: exactly what a repository depends on, from installed Python environments, lockfiles and manifests (Python, npm, Go) | Built |
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

## The inventory

For each package: its ecosystem (named as OSV names them: PyPI, npm, Go),
its name (normalised: PEP 503 for Python), its version, the file and line
it was found at, and **how sure** the version is:

| How | From | Means |
|-----|------|-------|
| installed | a Python environment's metadata (`*.dist-info/METADATA`) | what actually runs here |
| locked | `package-lock.json` (v2, v3), `go.mod`, `uv.lock`, `poetry.lock` | what an install gets |
| pinned | `==1.2.3` in a requirements file or pyproject; an exact version in a `package.json` | the one version a manifest allows |
| declared | a range (`fastapi>=0.142`) | which version is used is not known from this file |

- **Python environments matter most here.** Most of the projects this was
  built for declare only lower bounds and have no lockfile, so their exact
  versions exist only in their virtual environments. Each environment
  found (by its `pyvenv.cfg`) is read, never through a link: a `.venv/lib`
  linked out of the repository, a linked `.dist-info` folder or a linked
  metadata file is reported and skipped.
- **Local code is marked local** and will not be matched against
  advisories: an editable install of the project itself (any distribution
  with PEP 610's `direct_url.json`, which installers write only for
  something installed from a path or URL, not an index), `file:`/`git`
  dependencies, a Go module replaced by a folder, uv and Poetry path or VCS
  sources. npm workspaces, and the links to them, are the project's own
  folders and are left out of the inventory altogether.
- **Requirements files are read as pip reads them:** continuation lines
  joined first, then comments removed (tested against pip's own code);
  `-r` includes followed, but only to files inside the target that the
  walk saw (so never through a link or out of the target), and cycles end;
  `--hash` and other per-line options ignored; markers kept, not
  evaluated.
- **npm:** every installed copy in the lockfile, nested ones too
  (`node_modules/a/node_modules/b`); direct if installed at the top and
  named by the project or a workspace; scope from npm's own `dev` and
  `optional` flags. A `package.json` is read (as ranges) only when no
  lockfile in its folder or above covers it. Lockfile version 1 (npm 6) is
  named as not read, not misread.
- **Go:** `go.mod` only. Since Go 1.17 it lists every module the build
  needs (`// indirect` marks those only dependencies use); go.sum also
  lists modules needed only to check other go.mod files. `replace` is
  applied. The standard library is a dependency too ("stdlib"): pinned by a
  `toolchain` line, otherwise a range from the `go` line.
- **Not read, and said so:** yarn and pnpm lockfiles, Pipfile.lock,
  Java (Maven, Gradle), R (renv), Rust; Dockerfiles and Compose files wait
  for Milestone 5. Anything a reader cannot make sense of is a problem
  with its file and line; a file over 50 MB or not UTF-8 is a problem, not
  a crash.

### How it is tested

- **Each reader on fixtures** shaped like the real files (SyncBoard's
  workspaces lockfile, Gatekeeper's go.mod), with the awkward cases:
  hashes on continuation lines, `-e` with `#egg=`, direct URLs, markers,
  scoped and aliased npm names, nested copies, links, git sources,
  `devOptional`, quoted Go paths, replacements by version and by folder,
  a real virtual environment made by `python -m venv` compared with its own
  `pip list`.
- **Generated files** (Hypothesis): requirements files, npm lockfiles and
  go.mod files built from random packages come back exactly, on the right
  lines; line joining and comments agree with pip's own preprocessing on
  300 generated files; and any text or JSON at all never crashes a reader,
  and never yields a package whose name is not in the input.
- **13 planted bugs** each fail the tests (nested npm copies dropped, links
  read as packages, names not normalised, `// indirect` inverted, Go
  replacements ignored, optional dependencies dropped, includes leaving the
  target, wildcard pins counted as exact, comments removed before joining,
  three ways of reading through a link, editable installs not local).
- **Against the ecosystems' own tools, on my portfolio**
  (`scripts/check_inventory.py`): every one of 24 virtual environments
  matches its own `pip list`, all 3 npm lockfiles match `npm ls --all
  --package-lock-only`, and all 3 go.mod files match `go mod edit -json`
  (30 of 30; 668 environment packages, 814 npm, 14 Go). Those tools read
  the same files VulnScan reads, so this checks the reading, not the files.
- **On the whole portfolio:** 1,668 packages (835 PyPI, 816 npm, 17 Go: 668
  installed, 830 locked, 169 declared, 1 pinned; 28 local) in 0.4 s, with no
  problems; 43 files not read, each saying why.

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
| `src/vulnscan/inventory/__init__.py` | The inventory: each file to its reader, environments, includes, what is not read and why |
| `src/vulnscan/inventory/python.py`, `pep508.py` | Requirements files, pyproject.toml, uv.lock, poetry.lock, installed environments; requirement strings |
| `src/vulnscan/inventory/npm.py`, `golang.py` | package-lock.json and package.json; go.mod |
| `scripts/check_inventory.py` | The inventory against pip, npm and go, on real repositories |
| `tests/` | The walker (random trees with Hypothesis), the classifier, each reader (fixtures, generated files, fuzzing, pip as a reference), the CLI |
| `scripts/smoke.sh` | Checks the image from outside |

## Failures found while building it

1. **"foo>=" was read as a requirement.** The version pattern accepted any
   characters, so it read operator ">" and version "=". Found by a test of
   strings that must be refused; versions are now only the characters PEP
   440 uses.
2. **Comments were removed before continuation lines were joined,** the
   reverse of pip. In `pkg==1.0  # why \` pip treats the next line as part
   of the comment; this read it as a separate, unknown option. Found by a
   generated requirements file; confirmed in pip's source; now checked
   against pip's own preprocessing.
3. **Three planted bugs passed at first, and each taught something.** One
   plant was not the old behaviour at all (it removed comments after
   joining, as the fix does). "Follow links in environments" changed
   nothing, because `lib64` is never visited; the check guards a `lib`
   linked out of the repository, which led to finding that a linked
   `.egg-info` file or `METADATA` would have been read through its link
   (fixed, tested). And "editable installs not local" passed because two
   conditions said the same thing; PEP 610 makes one enough.
4. **The check against the real tools first skipped every environment**
   (a relative path to each interpreter, run from another folder) and
   reported SyncBoard's own workspace package as a difference (npm marks a
   workspace as `file:` only where it is installed, not where it is
   needed). Both were in the checking script, not in VulnScan; with them
   fixed, 30 of 30 match.
