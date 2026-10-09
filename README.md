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

> **Status:** Milestones 0-5 of 7. `vulnscan scan` finds a repository's
> Python, npm and Go dependencies (installed, locked, pinned or declared)
> and checks them against a local index of OSV's advisories, with version
> ordering and CVSS scoring written by hand: findings with severity and the
> version that fixes them, as text, JSON or SARIF, failing CI above a
> chosen severity unless accepted in a reviewed file. It also finds secrets
> (known token formats, private keys, JWTs, high-entropy values with a
> secret's name) in the files and in the whole git history, read by hand
> without running git, and never prints one. And it reads Dockerfiles and
> Compose files with its own parsers (checked against BuildKit and PyYAML)
> for risky settings: running as root, unpinned images, unchecked
> downloads, secrets in the image, privileged containers, the Docker socket,
> databases open to the network, default passwords.

## Status

| # | Milestone | Status |
|---|-----------|--------|
| 0 | Skeleton: Python 3.14 package, a `vulnscan scan PATH` CLI with text and JSON output and exit codes; ruff, mypy --strict, pytest + Hypothesis; a non-root image that scans a folder mounted read-only; CI; a smoke test | Built |
| 1 | Inventory: exactly what a repository depends on, from installed Python environments, lockfiles and manifests (Python, npm, Go) | Built |
| 2 | Advisory data from OSV in a local index; version ordering for PEP 440, npm SemVer and Go, written by hand; OSV's affected ranges | Built |
| 3 | Findings: packages matched to advisories, the fixing version, CVSS 3.1 scores; text, JSON and SARIF; `--fail-on`; a baseline file | Built |
| 4 | Secrets in files and git history, never shown in a finding | Built |
| 5 | Dockerfile and Compose rules | Built |
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

Secrets are part of every scan (`--no-secrets` leaves them out;
`--no-history` reads only the commit checked out):

```bash
make scan TARGET=../some-repo
docker run --rm --network none -v "$PWD:/scan:ro" vulnscan:local scan /scan --no-advisories
```

In CI (the SARIF can go to GitHub code scanning):

```bash
vulnscan update
vulnscan scan . --format sarif --output vulnscan.sarif --fail-on high
```

`make smoke` builds the image and checks it from outside (24 checks): it
runs unprivileged, scans fixtures mounted read-only with no network,
records a link out of the repository without following it, finds a
vulnerable dependency, three fake secrets (in HEAD, in history, in an
ignored file) and ten container rules, never prints a secret or a
password, and writes nothing into the target.

## What a scan reads

- **The target directory, and nothing outside it.** Symbolic links are
  listed, never followed: a link in a repository can point anywhere on the
  machine. Nothing is written.
- **Not walked:** `.git`, `node_modules`, `__pycache__` and tool caches.
  A `.git` folder marks a repository whose history the secret scan reads
  (by hand, read-only: see "Secrets"). A Python
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
  Java (Maven, Gradle), R (renv), Rust. (Dockerfiles and Compose files are
  not dependency files: the container checks read them.) Anything a reader cannot make sense of is a problem
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

## Findings

A scan matches every package with an exact version (installed, locked or
pinned) against the advisory index:

- **One finding per package occurrence and vulnerability.** Advisories
  that are aliases of each other (the same Go bug as GO-2024-2687 in Go's
  database and GHSA-4v7x-pqxf-cx7m in GitHub's) are one finding, listing
  every id; the preferred id first (GHSA, PYSEC, GO, MAL), CVE ids as
  aliases. The same package in two environments is two findings: each needs
  fixing.
- **Severity:** the highest CVSS 3.x base score among the advisories,
  computed here from their vectors (CVSS 3.1 §7.1, including its integer
  Roundup); a score of 9.0+ is critical, 7.0+ high, 4.0+ medium, else low.
  An advisory with only a CVSS 4.0 vector (not scored here: it is a
  different method) or none falls back to GitHub's own word, and the
  finding says which. A malicious package (OSV's MAL- reports) is critical
  by definition. Otherwise the severity is **unknown**, which never passes
  as harmless.
- **The fix:** the lowest version that fixes every advisory of the
  finding (from the ranges' "fixed" events above the version found), or
  "no fixed version has been published".
- **Undecided** (`possibly-vulnerable`): an advisory that could not be
  compared with the version (see "Is a version affected?"), with the
  reason. Reported, grouped by package, and never failing a scan.
- **Not matched, and counted:** local packages (the project's own code),
  and packages known only by a range: which version is used is not known.
  That includes Go's standard library in a module with no `toolchain`
  line (`go 1.27` only sets the oldest Go that may build it).

### Reports and exit codes

- `--format text` (for people; the default), `json` (schema 4: every
  finding with its package, file, line, advisories, aliases, severity and
  its source, vector, fix, references, a stable fingerprint, and whether it
  is accepted and failing; and the secrets, see "Secrets") or `sarif`
  (SARIF 2.1.0: one rule per advisory and per secret rule, with the
  `security-severity` GitHub uses, one result per finding at its file and
  line; checked against OASIS's schema).
- `--fail-on low|medium|high|critical|never` (default low): exit 1 if any
  decided, unaccepted finding is at or above it; an unknown severity is
  never below it. Exit 0 otherwise.
- **Exit 2 when the check could not be done:** no advisory data, or none
  for an ecosystem the repository uses (its packages are named as not
  checked). A scan that checked nothing must not pass CI; `--no-advisories`
  lists the inventory alone, on purpose. Advisories more than 7 days old
  are named in the report.

### Accepting a finding

In `.vulnscan.toml` at the root of the target (or `--baseline FILE`;
`--no-baseline` ignores it), kept in the repository so that accepting a
finding is a reviewed change:

```toml
[[accept]]
advisory = "CVE-2024-37890"    # any id or alias of the finding
package = "npm:ws"             # optional: this package only
reason = "no untrusted clients reach this server"
expires = 2026-12-31
```

A reason and an expiry date are required. An accepted finding is still
reported, as accepted (and as a SARIF suppression, with the reason), and
does not fail the scan, until its date passes: then it fails again, with a
note. An acceptance that matches nothing is reported, so the file does not
fill with entries for things long fixed. A file that is not valid (no
reason, an unquoted or timed date, an unknown key) stops the scan.

### How it is tested

- **Planted vulnerabilities** (`tests/test_findings.py`): a repository
  with known-vulnerable versions beside safe ones, scanned against six real
  advisories copied from OSV (`tests/data/osv`): a malicious npm package
  (critical), `ws` 8.17.0 (high, 7.5, fix 8.17.1), `golang.org/x/net`
  v0.22.0 (GitHub's and Go's advisories, one finding, 5.3, fix 0.23.0), a
  CVSS 4.0-only advisory (GitHub's rating), Django 3.2.18 and Go 1.22.1
  (no score given: unknown) are each found exactly; `ws` 8.17.1, Django
  4.2.16 and Flask 3.0.0 are not. The SARIF validates against the OASIS
  schema; thresholds, acceptances (by alias, by package, expired, unused)
  and missing data all behave as above.
- **CVSS:** every one of the 2,592 combinations of the eight base metrics
  scores exactly as the `cvss` library does (used only by the tests), and
  published scores of known vulnerabilities (Log4Shell 10.0) come out right;
  Roundup handles the floating-point case the specification warns about.
- **15 planted bugs** each fail the tests: privileges not adjusted when
  scope changes, Roundup by plain ceiling, the changed-scope impact formula
  cut short, aliases not merged, the fix taken from the first range or the
  lowest of a group, severity from the first advisory, unknown severity
  passing, undecided findings failing, expired or other packages'
  acceptances holding, unused ones not reported, an unchecked ecosystem
  passing, malicious packages not critical, SARIF without its
  security-severity.
- **Against GitHub's own ratings:** for the 11,175 GitHub advisories in the
  index with only a CVSS 3 vector, VulnScan's rating from the vector is
  GitHub's word in 11,085 (99.2%; `scripts/check_cvss.py`). Since the
  scores match the reference library everywhere, the other 90 are GitHub's
  choice of word. Where an advisory also has a CVSS 4.0 vector the match is
  69.5%: GitHub then rates by 4.0.
- **On my portfolio** (2026-10-08, with that day's advisories): 1,679
  packages; 1,479 checked, 172 known only as ranges, 28 local. **73
  findings** fail the default threshold (2 critical, 30 high, 40 medium, 1
  low) in 14 package versions across 14 projects, 68 of them packages
  installed in virtual environments (pip itself in most) and 5 from npm
  lockfiles; the decided ones are the advisories OSV's own service names
  (Milestone 2). 73 more are undecided: 72 are nine PyPA advisories for
  `torch` whose own ranges use versions that are not PEP 440
  ("2.6.0-cu124"), one a `go-redis` advisory with a range bound "9.6.0b1".
  The SARIF for the whole portfolio validates against the schema. A scan
  takes 1.5-2.3 s; the first after the update took 45 s, reading the 123 MB
  index from disk on a machine that was swapping.

## Secrets

Every scan looks for secrets in the target's files and in the history of
every git repository in it. **No output ever contains a secret:** a
finding gives its rule, file, line and column, the length, a format's fixed
prefix at most (`ghp_`, `AKIA`: the same in every token of that kind), and
a fingerprint.

### What is found

| Rule | Severity | Shape |
|------|----------|-------|
| `aws-access-key-id` | high | AKIA, ASIA, ABIA or ACCA, then 16 base32 characters |
| `github-token`, `github-fine-grained-token` | high | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36; `github_pat_` + 22 + `_` + 59 |
| `slack-token` | high | `xoxb-` (and a, e, o, p, r, s) with its numeric parts |
| `slack-webhook` | medium | `https://hooks.slack.com/services/...` |
| `stripe-secret-key`, `stripe-test-key` | high, low | `sk_live_`/`rk_live_`; `sk_test_` (test mode only). Publishable `pk_` keys are public and not found |
| `anthropic-api-key`, `openai-api-key`, `huggingface-token`, `groq-api-key` | high | `sk-ant-api03-...`; `sk-...T3BlbkFJ...` ("OpenAI" in base64); `hf_` + 34; `gsk_` + 52 |
| `google-api-key` | medium | `AIza` + 35: often public by design (a Maps key restricted to a site) |
| `private-key` | high; medium if encrypted | a `-----BEGIN ... PRIVATE KEY-----` block with at least 64 base64 characters and its END line, also with its lines joined by `\n` escapes (JSON) or quoted one per line (a notebook). Encrypted: PKCS#8 `ENCRYPTED`, legacy PEM's `Proc-Type: 4,ENCRYPTED`, or an OpenSSH key whose own header names a cipher |
| `jwt` | medium; low once expired | three base64url parts whose header is JSON with an `alg` (not `none`); the payload's `exp` says whether it has expired |
| `secret-assignment` | medium | a value of 16+ token characters, with letters and digits and at least 3.5 bits of Shannon entropy per character (hex: 32+ characters and 3.0), assigned to a name with a secret's word in it (`password`, `secret`, `token`, `credential`, `api_key`, `clientSecret`, `PASSWORD2`...) |

- **A token is never part of a longer one:** a match may not start or end
  inside a run of token characters (an `AKIA...` inside a base64 blob is
  not a key).
- **Placeholders are not secrets:** values containing `example`,
  `XXXXXX`, `****`, `placeholder`, `changeme`, `your_`, `redacted` or
  `dummy` (AWS's documentation key ends in `EXAMPLE`).
- **The name rule** reads a name's words (`snake_case`, `camelCase`,
  dotted keys; numbers are not words): `tokenizer`, `max_tokens` and
  `cache_key` are not secret names, and a name ending in a word about the
  secret (`_url`, `_file`, `_hash`, `_sha256`, `_id`, `_name`...) holds
  something else. Unquoted values (`KEY=value`, `key: value`) count only in
  `.env`, YAML, properties, INI and shell files and Dockerfiles; in code an
  unquoted value is a name.
- **Limits:** a password with spaces or symbols outside the token
  characters, one shorter than 16 characters or without digits, is not
  found by the name rule; nor is a secret passed in a call
  (`getenv("X", "...")`) rather than assigned. UTF-16 files read as
  binary.
- **Formats are written from the providers' documented shapes,** and
  tested with generated tokens of those shapes; no real token was used.
  GitHub's tokens carry a checksum, which is not checked. **Nothing is ever
  sent to a provider to ask whether a token works:** that would be a
  request to another system, which VulnScan does not make. A finding says
  "this looks like a credential", never "this credential is live".

### Where it is, and what to do

Every distinct file content (a git blob) reachable from any ref is scanned
once and mapped back to each path and commit that has it, so each finding
says where it is:

| State | Means | Fails the scan? |
|-------|-------|-----------------|
| `committed` | in the commit checked out (HEAD), at this path | yes |
| `history` | in an earlier commit, no longer at this path in HEAD: deleting the file did not remove it from anyone's clone | yes |
| `in-git` | in a commit, in a repository whose HEAD cannot be read (see below): whether the latest commit still has it is not known | yes |
| `file` | in a file outside any git repository (or one whose history or HEAD could not be read): whether it is committed is not known | yes |
| `uncommitted` | in the working tree only: an ignored `.env`, say, which is where a local secret belongs | no; reported |

Each committed or history finding also gives the first commit that has it,
and **whether it was pushed:** whether a commit with it is reachable from
a remote-tracking ref (`refs/remotes/...`, as of the last fetch). Pushed:
revoke it and issue a new one; rewriting history afterwards does not take
it back. Not pushed: it can still be taken out of the commits before
pushing. A working-tree file whose content is exactly HEAD's is not read
twice; an edited one is, and only what HEAD does not have is new.

**Which commit is HEAD** decides committed or not, so it is never guessed.
When iCloud has moved `.git/HEAD` or its branch's ref off the disk, HEAD is
read from its reflog (`.git/logs/HEAD`: git adds a line to it whenever HEAD
changes, so its last line is HEAD now), and the report says so. If the
reflog is not on the disk either, HEAD is unknown: findings in history are
`in-git` and in the working tree `file`, both failing. Never `uncommitted`,
which would pass: that was a bug in this milestone's first version (failure
14).

### Reading git without git

`src/vulnscan/git.py` reads `.git` directly: refs (loose and
`packed-refs`), loose objects (zlib), version 2 pack indexes and packs,
both kinds of delta (by offset and by id), commits, trees and annotated
tags; every object is checked against its SHA-1 name. Why not run `git`:

- **Running git in a repository runs that repository's configuration:**
  `core.fsmonitor`, `core.pager` and others name programs git starts. A
  scanner should be safe to point at any folder.
- **In the container the repository belongs to another user,** and git
  refuses it ("dubious ownership"); the image has no git at all.
- **Nothing is written** (git may refresh its index even for a read).

Not read, and said so: SHA-256 repositories, `objects/info/alternates`
(object stores elsewhere), version 1 pack indexes, a `.git` that is a file
(a worktree or submodule pointing elsewhere), links anywhere under `.git`.
Missing objects (shallow or partial clones) are counted. Commit messages
are not scanned.

### Files that are not on this disk

On macOS with iCloud's "Optimise Mac Storage", a file can be a
placeholder whose content is in the cloud: reading it downloads it.
VulnScan never reads one. The first scan of my portfolio stalled for
minutes downloading them (782 working-tree files, 573 MB, on a disk 98%
full; then 12 s per 41-byte ref). Placeholders in the working tree are
listed, with whether git has a committed version (which the history scan
did read); placeholders under `.git` are counted per repository, and the
report says that repository's history may be incomplete.

### Accepting a secret

By fingerprint, in `.vulnscan.toml`, with a reason and an expiry date like
any acceptance:

```toml
[[accept]]
secret = "a38f66b9bc2437db"
reason = "a fake key the tests are built around"
expires = 2027-03-31
```

A `secret` that is not a 16-hex-digit fingerprint stops the scan, and the
error does not repeat it. **The fingerprint is a slow hash** (PBKDF2-SHA256
of the value, 100,000 rounds; 64 bits shown): it is printed and committed
in baseline files, and a fast hash of a guessable value would let anyone
test guesses against it at billions per second.

### How it is tested

- **The git reader against git itself** (`tests/test_git.py`, with
  repositories made by git in the tests, isolated from any user
  configuration): every object of a history read exactly as `git cat-file`
  gives it, loose and after `git repack` with offset deltas and with
  reference deltas (`repack.useDeltaBaseOffset=false`); every commit's
  files, and each file's first commit, as `git ls-tree` gives them, on
  fixed histories and 25 random ones (edits, deletions, branches, packed or
  not); pushed and not pushed after a clone and a fetch; a shallow clone; a
  SHA-256 repository refused; a linked ref not followed; damaged objects an
  error, not a wrong answer. On 3 of my repositories (1,779 objects, one
  with 126 commits) every object matched `git cat-file`.
- **Each format, from generated fakes, in 7 forms** (bare, quoted, `KEY=`
  right after `=`, YAML, JSON, an `Authorization` header, a notebook's
  escaped source line): found exactly where it is, shown only as its prefix
  and length; never part of a longer token; never as a placeholder. Real
  private keys made for the test by `ssh-keygen` and `openssl`, with and
  without a passphrase. JWTs live, expired and unsigned. 14 assignment
  forms across languages and config files found; 13 names and 9 values
  that are not secrets not found. 300 random texts never break the rules,
  and 200 tokens planted in random surroundings are each found where they
  are.
- **No fake secret is written in the tests:** each is built at run time
  from random characters (`tests/helpers.py`), so VulnScan scanning its own
  repository finds nothing, and a push of it carries no token.
- **End to end** (`tests/test_secrets.py`): a repository with a token in
  HEAD (kept through an edit), one only in pushed history, one committed
  but not pushed, an ignored `.env`, an uncommitted edit, a binary file and
  a link out of the target, beside a folder outside git with a JWT and a
  private key: each found in the right state, with its first commit, line
  and pushed flag; decoys not found; **no planted secret (no 8 characters
  of its random part) in the text, JSON or SARIF output**; acceptance by
  fingerprint, expiry, unused acceptances; a baseline holding a secret
  refused without repeating it; placeholder files not read.
- **22 planted bugs** each fail the tests: git's offset-delta encoding,
  a 64 KiB copy, objects not checked against their names, pushed not
  upgraded, newest commit first, links under `.git` followed, links and
  submodules read as files, the shallow boundary ignored, `=` before a
  token, placeholders reported, the value shown, unsigned JWTs, encrypted
  keys ranked as plain, numbers as words, an entropy threshold of 2.0,
  bare values in code, an edited file's committed secret reported twice,
  the later commit as first, placeholder files read, uncommitted secrets
  failing, expired acceptances holding, repositories not found. Two passed
  at first (pushed, and the entropy threshold): the tests had no case for
  them, and now do.
- **The image** (`make smoke`, 21 checks): a repository made on the host,
  mounted read-only, owned by another user, scanned with no network and no
  git: three fake tokens found in HEAD, in history and in an ignored file,
  none printed in any format, nothing written.

### On my portfolio (2026-10-09)

The whole `projects` folder: 31 git repositories, 298 commits, 2,351
distinct file versions and 2,836 working-tree files read. A scan took 12
to 50 s across four timed runs on one 8 GB M2 laptop; the spread is not
explained, and scan time is measured properly in Milestone 6.

- **The first run found 4.** Three were a SHA-256 hash named
  `token_lengths_sha256` (in two versions of a loraforge-llm evidence
  file); one was a real API key in papertrail-rag's `.env`, correctly
  `uncommitted` (the file is git-ignored and was never committed). That run
  exposed two bugs, fixed after seeing it: the name rule read "256" as the
  name's last word, and the format rules missed **every** `KEY=token` line,
  because `=` counted as part of a token (the key had been found only by
  its name). Since the fixes were made on this data, it is not an
  independent measurement.
- **After the fixes: 1 finding,** the same key, now named as a Groq key,
  not failing. **No committed secret** in what could be read.
- **What could not be read:** 782 working-tree files are iCloud
  placeholders (753 not scanned, mostly generated `.json`, `.png` and
  `.npz` outputs; 29 have a committed version, which was scanned); and
  files under `.git` are placeholders in 17 repositories (1 to 48 each,
  including 45 objects across 7 of them), so their history may be
  incomplete. iCloud moves more out as the disk fills: the counts grew
  between two runs an hour apart.
- **False positives on other people's code:** 25,777 files of installed
  packages (three Python environments' `site-packages`, two
  `node_modules`) gave 2 findings, both a JWT in `zod`'s own tests (a
  token's shape used as test data). Nothing that is not a credential was
  found.

## Dockerfiles and Compose files

Every scan reads the target's Dockerfiles (`Dockerfile`, `Containerfile`,
`Dockerfile.*`, `*.Dockerfile`) and Compose files (`compose.yaml`,
`docker-compose.yml`, `compose.*.yaml`...) with parsers written for this,
and reports risky settings. A finding says what is wrong in words, never
with a value that could be a secret ("POSTGRES_PASSWORD is the same as
POSTGRES_USER", not the password), and how to fix it.

### What is found

| Rule | Severity | When |
|------|----------|------|
| `dockerfile/runs-as-root` | medium | an image the file makes ends with `USER root` (or `0`), or has no USER and its base image is not one known to set a non-root user (`:nonroot` tags, Chainguard's images); most base images run as root |
| `dockerfile/base-image-unpinned` | medium | `FROM` (or `COPY --from`) an image with no tag or `:latest` |
| `dockerfile/base-image-no-digest` | low | an image pinned by tag only: a tag can be moved to a different image; a digest (`@sha256:...`) cannot |
| `dockerfile/add-from-url` | medium | `ADD https://...` (or a git repository) without `--checksum` |
| `dockerfile/pipe-to-shell` | medium | a download run as code unchecked: `curl ... \| sh`, `bash <(curl ...)`, `sh -c "$(wget -O- ...)"`, `eval "$(...)"`, also inside `sh -c '...'`, exec form and heredocs |
| `dockerfile/secret-in-env` | high | `ENV` with a secret's name (the same name rule as for secrets) and a value: stored in the image, for anyone with it to read (`docker inspect`) |
| `dockerfile/secret-in-arg` | medium; high with a default | `ARG` with a secret's name: build arguments are kept in the image's history and build provenance |
| `dockerfile/no-healthcheck` | low | an image that EXPOSEs a port has no HEALTHCHECK (`HEALTHCHECK NONE` counts as a decision) |
| `compose/privileged` | high | `privileged: true`, or `cap_add` with `ALL` or `SYS_ADMIN` |
| `compose/host-namespace` | medium | `network_mode`, `pid`, `ipc`, `uts` or `userns_mode` set to `host` |
| `compose/docker-socket` | high | the Docker socket mounted into a container (read-only too: it is an API, and whoever controls Docker controls the host) |
| `compose/database-port-published` | medium | a database's port (Postgres, MySQL, MariaDB, MongoDB, Redis, Valkey, Memcached, Elasticsearch and others, by image) published on every interface: `"5432:5432"`, `"5432"`, `0.0.0.0`, or a long form without `host_ip` |
| `compose/default-password` | medium; high for none | a password variable (or a URL's password) that equals the user or database name, the service's or image's name, or a well-known default; a `${VAR:-default}` is judged by its default. High: settings that allow no password (`POSTGRES_HOST_AUTH_METHOD: trust`, `MYSQL_ALLOW_EMPTY_PASSWORD`) |

- **Which images a Dockerfile makes:** every stage that no later stage
  builds on (`FROM stage`), copies from (`COPY --from`) or mounts
  (`RUN --mount=from=`): the last stage, and stages built with
  `--target`. A build stage that only feeds another is not judged as an
  image anyone runs. `USER`, `EXPOSE` and `HEALTHCHECK` are inherited from
  the stages a stage builds on.
- **Build arguments** before the first `FROM` are filled in where they
  have defaults (`FROM python:${V}-slim`); an image chosen by an argument
  with no default is not judged.
- **One password written once** (in a YAML anchor) and used by several
  services is one finding, naming them all.
- **Accepting a rule,** everywhere or in one file, in `.vulnscan.toml`:
  `rule = "dockerfile/no-healthcheck"`, optional `path = "bench/Dockerfile"`,
  with a reason and an expiry date. An unknown rule stops the scan.
- **Not covered:** `ONBUILD` instructions (they run in other images),
  a `SHELL` that changes the shell, Compose's `extends`, `include` and
  `env_file`, variables from `.env` files, a download stored in a variable
  and run later (`x=$(curl ...); echo $x | sh`), a download saved to a file
  and run without a check (only the pipe forms are found), and anything
  across files: a healthcheck in Compose does not silence the Dockerfile's
  finding.

### Reading the files

- **Dockerfiles as BuildKit reads them** (`containers/dockerfile.py`):
  parser directives (`# escape=` changes the continuation character), a
  first line's leading whitespace removed, continuation lines appended as
  they are, comment lines and empty lines inside a continued instruction
  skipped, a `#` after an instruction kept as part of it, flags, JSON
  (exec) form only when the whole rest is a JSON array of strings, heredocs
  (`<<EOF`, `<<-EOF`, quoted names, several on one line, CR kept in their
  bodies as BuildKit keeps it).
- **The part of YAML Compose files use** (`containers/yamlsub.py`): block
  and flow collections, three kinds of scalar, block scalars with every
  chomping, comments, anchors, aliases and merge keys. Every scalar is kept
  as written, as text. Refused with the line, never guessed at: tags (Compose's
  `!reset`), several documents, `?` keys, quoted strings over several
  lines, explicit block indentation, duplicate keys, tabs. VulnScan still
  has no runtime dependencies.
- **A file that is not on this disk** (an iCloud placeholder) is read from
  git's HEAD instead, and its findings say so; if HEAD's copy is not on
  the disk either, it is named as not read, with the reason.

### How it is tested

- **The Dockerfile parser against BuildKit itself.** `scripts/buildkit_parse`
  is a small Go program that prints BuildKit's own parse
  (github.com/moby/buildkit v0.34.0); `scripts/check_dockerfile_parser.py`
  compares the two on real and generated Dockerfiles (continuations with
  comments and blank lines inside, spaces after the escape, heredocs, JSON
  arrays that are and are not exec form, the backtick escape, CRLF). On
  3,016 Dockerfiles (16 of mine, 3,000 generated) every one BuildKit
  accepts, 2,687, is parsed the same: instructions, first and last lines,
  text, flags, form, heredocs. The other 329 are generated files BuildKit
  rejects as unbuildable (LABEL without `key=value`, say), which VulnScan
  reads anyway. BuildKit's answers for 18 hard cases are recorded in
  `tests/data/buildkit`, so the tests check against BuildKit without Go;
  where the tool is built, 200 generated files are also compared live.
- **The YAML reader against PyYAML** (used only by the tests, every scalar
  read as a string, merge keys applied): documents PyYAML writes in block,
  flow, literal and folded styles, with shared objects as anchors and
  aliases (Hypothesis; documents without line breaks in their strings must
  never be refused); keys made of YAML's own characters; hand-written
  merges, block scalars and comments; three of my Compose files copied
  into `tests/data/compose`. Outside the tests: all 94 YAML files in my
  portfolio (Compose files, CI workflows, ROS 2 parameters, PyTorch's own
  YAML) are read exactly as PyYAML reads them (75) or refused (19:
  several documents, or a quoted string over several lines), none misread;
  and 30,000 generated documents with keys of any characters: 7,137 read,
  all exactly, the rest refused.
- **Every rule fires and does not fire** (`tests/test_containers.py`, 82
  tests): each form of each rule, the cases next to it that must stay
  quiet (`127.0.0.1:5432:5432`, `[::1]`, a digest, `HEALTHCHECK NONE`, a
  password from `${PG_PASS}`, `POSTGRES_PASSWORD_FILE`...), and no password
  or secret value in any message, text, JSON or SARIF (the SARIF validated
  against the OASIS schema).
- **38 planted bugs** each fail the tests (the YAML merge order, chomping,
  folding, comments, sequences at a key's indentation, escapes, `?` keys,
  a nameless alias, a key split at the wrong ": "; BuildKit's comment, blank-line, escape, CR and
  directive rules; pipelines, `sh -c`, substitutions; each rule's own
  conditions; the baseline's path and unknown rules; and HEAD's
  reflog). Two passed at first. One test checked only an exit code that
  other findings kept at 1, and now checks the finding. One plant was in
  code that, after another fix, changed nothing; that code was removed.
- **The image** (`make smoke`, 24 checks): a risky Dockerfile and Compose
  file, mounted read-only with no network: ten rules found, no password
  printed.

### On my portfolio (2026-10-09)

33 files: 23 Dockerfiles and 10 Compose files. 27 were read. The 6 others
are iCloud placeholders whose committed copies are placeholders too, so
neither copy is on this disk (each named, with the missing object). **49
findings in 20 files, each labelled by hand:**

| Rule | Findings | Labelled |
|------|----------|----------|
| `base-image-no-digest` | 26 | all true: no image in the portfolio is pinned by digest |
| `runs-as-root` | 9 | all true: python-slim, ROS, CUDA and nginx images with no USER (all of those run as root) |
| `default-password` | 6 | all true: LinkForge, PaperTrail and SurgiServe use the user name as the database password (local development defaults, said so in SurgiServe's file) |
| `no-healthcheck` | 5 | 4 true; 1 false in context: LinkForge's API has a healthcheck in its Compose file, which this rule cannot see |
| `database-port-published` | 3 | all true: LinkForge's Postgres and Redis and PaperTrail's Postgres listen on every interface, two of them with the user name as the password |

48 of 49 say something true. What matters most: in LinkForge and
PaperTrail, `docker compose up` puts a Postgres whose password is its user
name on every network interface of the machine, so anyone on the same
network could log in while it runs. SurgiServe and Gatekeeper already bind
theirs to 127.0.0.1. Nothing has been changed in those repositories:
Milestone 6 decides fixes with me. A first test with these files ran into
a placeholder Dockerfile, and that led to a bug in Milestone 4's secret
scan (failure 14).

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
| `src/vulnscan/findings.py` | Matching the inventory to advisories: grouping aliases, severity, the fix |
| `src/vulnscan/cvss.py` | CVSS 3 base scores, from the vector |
| `src/vulnscan/baseline.py` | Accepted findings (`.vulnscan.toml`) |
| `src/vulnscan/sarif.py` | Findings as SARIF 2.1.0 |
| `src/vulnscan/git.py` | Reading `.git` by hand: refs, loose objects, packs and deltas, commits and trees; the history walk |
| `src/vulnscan/secrets/rules.py` | What a secret looks like: formats, private keys, JWTs, high-entropy assignments; redaction; the fingerprint |
| `src/vulnscan/secrets/__init__.py` | The secret scan: history and working tree, states, pushed, acceptances |
| `scripts/show_context.py` | The lines around each secret finding, with values masked, for labelling by hand |
| `src/vulnscan/containers/__init__.py` | The Dockerfile and Compose rules; reading a file, or its committed copy; acceptances by rule |
| `src/vulnscan/containers/dockerfile.py` | Dockerfiles, read as BuildKit reads them; words and ENV/ARG pairs |
| `src/vulnscan/containers/yamlsub.py` | The part of YAML Compose files use |
| `src/vulnscan/containers/shell.py` | A RUN line's commands, pipelines and substitutions; downloads run as code |
| `scripts/buildkit_parse/`, `scripts/check_dockerfile_parser.py` | BuildKit's own parse (a Go development tool), and the comparison with it |
| `tests/helpers.py` | Repositories made with git; fake secrets built at run time |
| `scripts/check_cvss.py` | The computed ratings against GitHub's |
| `tests/data/` | Six real advisories and the OASIS SARIF schema, with where they came from |
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
7. **Two tests read my real advisory data.** Scans began to need the index,
   and the CLI tests that did not name a data folder found the one in
   `~/.cache`. Every test now gets an empty data folder unless it builds
   its own (a pytest fixture), so no test depends on this machine.
8. **A smoke check could fail by the clock.** "Nothing written into the
   target" compared folder listings after the script had itself written
   and removed a `.vulnscan.toml` there; the folder's time changed, and only
   the listing's minute resolution hid it. The check now runs before the
   script writes anything.
9. **The first portfolio secret scan stalled,** at 0% CPU: reading every
   working-tree file made iCloud download its placeholders (782 files,
   573 MB, onto a disk 98% full), then 12 s per 41-byte ref under `.git`.
   I stopped it; placeholders are now never read, and the report says what
   was missed.
10. **Every `KEY=token` line was missed.** A token may not start inside a
    longer run of token characters, and `=` was one of them, so a token
    right after `=` (an `.env` file's form) never matched. The real key in
    papertrail-rag's `.env` was found only by its name; asking why a Groq
    rule did not fire showed it. `=` only ends base64 (padding), so it may
    come before a token; the `.env` form is now tested for every format.
11. **A hash was called a secret.** `token_lengths_sha256` split into the
    words token, lengths, sha, 256: the last word "256" is not one that
    says a name holds something about a secret, so its hex value counted.
    Numbers are no longer words.
12. **Two planted bugs passed at first.** "Pushed not upgraded" had no
    case where content is committed unpushed first and pushed later; and my
    low-entropy test value `abc123...` is all hex digits, so the hex rule
    refused it before the entropy threshold mattered. Both tests added.
13. **Two of my own tests were wrong:** one made a branch before any
    commit (git refuses), and one expected a variable-length token followed
    by a letter not to match, when the longer run is itself a token of that
    shape. Both corrected; what is tested now is that a match never stops
    inside a longer run.
14. **Milestone 4 could have passed a committed secret.** Reading
    Dockerfiles that are iCloud placeholders from git's HEAD reported
    "not committed" for files that are on GitHub: iCloud had moved
    `refs/heads/main` off the disk, so HEAD resolved to nothing, which the
    code took as "no commits". The secret scan made the same mistake. Every
    secret in such a repository's working tree would have been
    `uncommitted`, which never fails. None was found there, so no output
    was wrong, but only by luck. HEAD unknown is now its own case (`in-git`,
    `file`), and HEAD is read from its reflog when that is on the disk (all
    31 repositories, on 2026-10-09; used for 16).
15. **The first reference was not a reference.** The `dockerfile-parse`
    library ends an instruction at an empty line inside a continuation;
    BuildKit skips the line and continues. So the check is against
    BuildKit's own parser instead, through a small Go program.
16. **BuildKit disagreed with my parser four times**: an instruction's
    trailing whitespace (BuildKit keeps it), JSON form for COPY, ADD and
    VOLUME, a JSON array after `HEALTHCHECK NONE`, and a CR in heredoc
    bodies (found by the live comparison, after the recorded cases all
    passed). All fixed; 0 differences on 3,016 files since.
17. **The YAML reader got five things wrong.** A document that is one flow
    mapping was read as a `key: value` line, because brackets inside a
    quoted string were counted; a stricter property test (strings without
    line breaks must never be refused) found it. Then keys made of YAML's
    own characters, which the first generators never produced, showed `? `
    keys inside `{ }` read as text (72 of 3,000 documents misread) and a
    bare `*` crashing the reader. And the strict test, run again, found
    `-?` refused as a value: `rest in "-?:"` meant "one of these three
    characters" but tests for a substring. Another run found `0]: {...}`
    split inside the braces: the key splitter counted brackets, but a plain
    key may hold them; the first ": " ends it. All five read right or
    refused now, and each has a test.
18. **One password counted three times.** SurgiServe's database URL is one
    YAML anchor used by three services, and was three findings; it is one
    now, naming the services.
19. **Two planted bugs passed at first** (see "How it is tested" under
    Dockerfiles and Compose files): a weak test, strengthened, and code
    that a later fix had made redundant, removed.
