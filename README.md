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

> **Status:** Milestones 0-2 of 7. `vulnscan scan` walks a repository and
> builds its inventory: every Python, npm and Go package it depends on,
> with the version and how sure that version is. `vulnscan update` keeps a
> local index of OSV's advisories, and `vulnscan lookup` says which affect
> one package version, with version ordering written by hand. Scans do not
> use the advisories yet (Milestone 3), so they report no findings.

## Status

| # | Milestone | Status |
|---|-----------|--------|
| 0 | Skeleton: Python 3.14 package, a `vulnscan scan PATH` CLI with text and JSON output and exit codes; ruff, mypy --strict, pytest + Hypothesis; a non-root image that scans a folder mounted read-only; CI; a smoke test | Built |
| 1 | Inventory: exactly what a repository depends on, from installed Python environments, lockfiles and manifests (Python, npm, Go) | Built |
| 2 | Advisory data from OSV in a local index; version ordering for PEP 440, npm SemVer and Go, written by hand; OSV's affected ranges | Built |
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

Advisory data (the only network VulnScan uses), then a lookup:

```bash
make update                      # OSV's exports for PyPI, npm and Go, into ~/.cache/vulnscan
make lookup Q="PyPI django 3.2.18"
docker run --rm -v ~/.cache/vulnscan:/data vulnscan:local update
docker run --rm --network none -v ~/.cache/vulnscan:/data:ro vulnscan:local lookup npm ws 8.17.0
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

## Advisory data

`vulnscan update` downloads OSV's export for each ecosystem (one zip of
JSON advisories each, from OSV's public bucket) and indexes it in SQLite at
`~/.cache/vulnscan/osv.sqlite` (or `$VULNSCAN_DATA`), outside any
repository. It is the only command that uses the network; scans and
lookups read the index, read-only, and run with no network at all.

- **A download is checked before it is used:** streamed to a `.part`
  file, kept only if its length is the server's and its MD5 matches the
  one the server publishes for the object (the `x-goog-hash` header); its
  SHA-256 is recorded, to say exactly which data a scan used. A bad
  download leaves nothing behind, and the zip is deleted once indexed
  (`--keep` keeps it).
- **An ecosystem is replaced all at once,** in one transaction: an update
  that fails part-way leaves the previous data. Withdrawn advisories are
  left out; an advisory that does not parse is counted, not indexed; a zip
  entry over 5 MB is refused without being read into memory.
- **What is kept** of an advisory: its id, aliases (CVE ids), summary,
  CVSS vectors, GitHub's severity word, ten references, and its affected
  entries for PyPI, npm and Go (advisories often cover other ecosystems
  too). Not the long description.
- **On 2026-10-08:** PyPI 25,584 advisories (616 withdrawn left out), npm
  229,488 (730), Go 9,399 (161); 266 MB downloaded, all three MD5-checked;
  an index of 123 MB; 22 s on this machine's connection, once. npm's count
  is mostly malicious-package reports (OSV's `MAL-` advisories).
  `--from ECOSYSTEM=ZIP` indexes an export already on disk instead.

### Ordering versions

Written by hand, from the specifications (`src/vulnscan/versions/`):

- **Python (PEP 440):** epochs, pre-releases (a, b, rc and their other
  spellings), post- and dev releases, local versions, and the PEP's
  normalisation ("1.0-ALPHA.1" is "1.0a1"; "1.0" is "1.0.0"; "v" and case do
  not matter), using the PEP's own pattern.
- **npm (SemVer 2.0.0):** strict, as semver.org's own expression accepts;
  pre-releases before the release, identifiers compared numerically or as
  text, build metadata ignored.
- **Go:** module versions are SemVer with a "v" (pseudo-versions are
  pre-releases; "+incompatible" is build metadata). The standard library's
  versions are Go's own ("go1.21rc2"), converted as the Go vulnerability
  database writes them (1.21.0-rc.2).

### Is a version affected?

As the OSV schema's "Evaluation" section says: in the advisory's explicit
list of versions, or inside one of its ranges, whose events are sorted by
version and walked in order (introduced, fixed, last_affected; limit caps
the range). The answer is **affected**, **not affected**, or **unknown**,
never a guess: unknown when the version, or an event of a range, is not a
version in that ecosystem's ordering, or when only a GIT range (commits)
covers it and there is no list.

### How it is tested

- **Version ordering against reference implementations** (Hypothesis,
  2,000 generated cases each; `packaging` and `semver` are used only by
  the tests): PEP 440 accepts exactly the strings `packaging` accepts,
  normalises them the same, and orders every pair the same; SemVer the
  same against the `semver` library; plus the PEP's and semver.org's own
  ordering examples, and Go's pseudo-versions and toolchain names.
- **Evaluation:** the schema's examples (unfixed, fixed, several ranges,
  last_affected, limit), events in any order, the explicit list compared
  as versions ("1.0" lists "1.0.0"), GIT ranges with and without a list;
  and random disjoint intervals of versions, as one range's events in a
  random order, where every version must come out exactly inside or out.
- **The index and the download:** a real zip indexed and looked up (OSV's
  "Django" found as "django"), withdrawn and broken entries counted, an
  update that fails part-way leaving the old data, a read-only index that
  is never written to, and a local HTTP server serving a good download, one
  with the wrong MD5, one cut short and a 404 (nothing left behind).
- **17 planted bugs** each fail the tests: pre-release order, trailing
  zeros, dev releases, local versions, a release before its pre-releases,
  pre-release numbers compared as text, Go's "v", events walked unsorted,
  last_affected as fixed, limit ignored, the list compared as text, GIT
  ranges treated as fixed, names not normalised, withdrawn advisories
  kept, MD5 not checked, a partial file left, and an update that was not
  all-or-nothing.
- **Against OSV's own lists, on all the real data**
  (`scripts/check_ranges.py`): OSV adds to most advisories the list of
  affected versions it worked out from the ranges, so each listed version
  should come out affected from the ranges alone. PyPI: 1,341,111 of
  1,344,713 do (99.7%); 3,558 are unknown (versions that are not PEP 440,
  such as "0.1-bulbasaur"); 44 are not, all in advisories whose ranges are
  malformed (several last_affected events in one range, two ranges written
  as one, a listed pre-release below where its range starts). npm: 26,014
  of 26,144; the 130 others are malicious-package reports listing versions
  below where their range starts. Go: 168 of 169, one unknown. Those
  disagreements do not reach an answer: the explicit list is checked
  first, so a listed version is affected.
- **Against OSV's own evaluation, on my portfolio**
  (`scripts/check_against_osv_api.py`, a development check that sends the
  packages' public names and versions to OSV's query API): for all 761
  registry packages with an exact version, VulnScan's local index names
  exactly the advisories OSV's service does, 83 of them in all.

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
| `src/vulnscan/versions/` | Version ordering by hand: PEP 440, SemVer, Go |
| `src/vulnscan/advisories/osv.py` | Reading an advisory, and the OSV evaluation |
| `src/vulnscan/advisories/db.py`, `fetch.py`, `__init__.py` | The SQLite index; the checked download; update and lookup |
| `scripts/check_ranges.py`, `scripts/check_against_osv_api.py` | The evaluation against OSV's lists, and against OSV's own service |
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
5. **A test was wrong about PEP 440.** I listed "1.0-dev-" as invalid; my
   parser accepted it, and so does `packaging` (a separator may follow
   "dev" with no number: it is 1.0.dev0). The test was corrected, not the
   parser.
6. **The first check against OSV's lists reported thousands of
   disagreements in Go** (4,504 of 5,951). An export is one ecosystem's,
   but its advisories also cover packages of others (the same GitHub
   advisory lists a Go module and a Ruby gem); the check script counted
   the gem's versions. Restricted to the export's own ecosystem: 168 of
   169. The evaluation itself had been right, and says "unknown" for an
   ecosystem it cannot order.
