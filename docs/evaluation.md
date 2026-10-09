# VulnScan on my own repositories (Milestone 6)

Everything VulnScan reports about my portfolio, checked: every finding
labelled by hand, the dependency findings cross-checked against another
tool, and how long a scan takes. 2026-10-09.

- **Target:** the `projects` folder: 31 git repositories, 5,077 files (74
  of them manifests, lockfiles or container files), 24 Python environments.
- **Advisory data:** OSV's exports downloaded that day (all MD5-checked):
  PyPI 25,596 advisories (export SHA-256 `62e774fcfbd4...`), npm 229,527
  (`acecd5bcaae5...`), Go 9,407 (`c5917219dc7d...`).
- **Reference:** osv-scanner 2.6.0 (Homebrew), only as a cross-check, with
  its offline databases downloaded the same hour from the same source.
- **Machine:** one 8 GB M2 MacBook Air, macOS, Python 3.14; the folder is
  iCloud-synced and the disk 97% full (see "What could not be read").

## Dependencies

2,045 packages (1,206 PyPI, 816 npm, 23 Go; 1,032 installed, 835 locked,
177 declared ranges, 1 pinned; 28 the projects' own code). 1,841 were
checked against the advisories.

### Against osv-scanner

`scripts/compare_osv_scanner.py` matches the two tools' results by
package occurrence (ecosystem, name, version, file) and their advisory
groups by shared ids and aliases.

osv-scanner was run over the same tree, reading lockfiles and installed
Python packages (`--experimental-plugins lockfile --experimental-plugins
python/wheelegg`, `--no-ignore` so git-ignored environments are read too,
`node_modules` excluded as VulnScan excludes it).

**The first comparison found a gap in VulnScan.** On the packages both
tools found, they agreed exactly: all 73 of VulnScan's findings, nothing
osv-scanner reported that VulnScan did not. But osv-scanner also read the
SBOM that pip ships for the packages it bundles (`pip/_vendor/bom.cdx.json`),
and found 78 more advisory groups there: pip's copies of urllib3 2.7.0,
msgpack 1.1.2 and setuptools 70.3.0, in 13 environments. VulnScan did not
read code bundled inside other packages at all.

So VulnScan now reads bundled packages too (`inventory/sbom.py`): metadata
under `<package>/_vendor` (setuptools keeps `.dist-info` folders there),
pip's SBOM, and SBOMs in `.dist-info/sboms` (PEP 770), each marked
"bundled in <package>", with a fix that names the package to upgrade. That
is a change made after seeing the comparison, and the comparison was run
again:

| | Before | After |
|---|---|---|
| Package occurrences: VulnScan, osv-scanner, both | 1,485, 2,104, 1,484 | 1,839, 2,104, 1,838 |
| Advisory groups both tools report | 73 | **151** |
| Reported by osv-scanner only (on packages both found) | 0 | **0** |
| Reported by osv-scanner only (on packages only it found) | 78 | **0** |
| Reported by VulnScan only | 64, all undecided | 64, all undecided |
| Severity score the same, where both give one | 25 of 26 | 64 of 65 |

The one severity difference: GHSA-68fv-2mgg-jv7q (source-map-js) has a
CVSS 3.1 vector (7.5) and a CVSS 4.0 vector (8.7); osv-scanner shows the
higher, VulnScan scores CVSS 3 only (as its README says).

**What each tool reads that the other does not** (none of it with an
advisory today):

| Only osv-scanner | Packages | Why |
|---|---|---|
| Pillow's SBOM entries | 96 | Pillow's own C extensions (`pkg:pypi/pillow@12.3.0#c-ext/...`), which osv-scanner names as packages ("pil-avif"); VulnScan reads them as part of Pillow |
| The projects' own code | 50 | editable installs and `src/*.egg-info`: VulnScan marks them local, by design |
| R (`renv.lock`) | 99 | not covered by VulnScan |
| Java (`pom.xml`) | 15 | not covered by VulnScan |
| npm workspace packages | 6 | SyncBoard's own packages: left out by design |

| Only VulnScan | Packages | Why |
|---|---|---|
| A pin in `pyproject.toml` | 1 | torch 2.13.0 in SurgiServe: osv-scanner does not read pyproject pins |

### Every finding, labelled

151 decided findings in 17 package versions, and 73 undecided. "True"
means the advisory's affected versions include the version found (both
tools agree on all 151); the labels by hand say what that means here.

| Package | Where | Findings | Label |
|---|---|---|---|
| urllib3 2.7.0, bundled in pip | 13 environments (pip 26.2 and 26.2.1) | 39 | true: pip carries all of urllib3, and uses it to download |
| setuptools 70.3.0, bundled in pip | 13 | 26 | **matches by version, but the vulnerable code is not there**: the advisories are about `setuptools.package_index` and its `sdist` command; pip bundles only `pkg_resources` from setuptools. A limit of matching by SBOM version; both tools report them |
| msgpack 1.1.2, bundled in pip | 13 | 13 | true: pip carries msgpack (its HTTP cache) |
| pip 26.0, 26.1.2, 24.0 | 11 environments | 34 | true |
| pypdf 6.14.2, 6.16.1 | resume-radar, kernelforge-cuda | 22 | true |
| urllib3 2.7.0 | loraforge-llm, textforge-finetune | 6 | true |
| mako 1.4.1, multidict 6.7.1, accelerate 1.14.0, cryptography 49.0.0 | papertrail-rag (2 environments), loraforge-llm, textforge-finetune, resume-radar | 6 | true |
| tinypool 1.1.1 (critical, 2), vitest and @vitest/mocker 3.2.7, source-map-js 1.2.1 | linkforge-fullstack's web app | 5 | true, and development-only (the test runner): not in what the app ships |

**The 73 undecided** (VulnScan reports them and does not fail on them):
nine PyPA advisories for torch whose own ranges end at "2.6.0-cu124",
"2.6.0-NA" or "2.7.1-NA" (not PEP 440 versions), in 7 environments and
SurgiServe's pin (72), and one go-redis advisory with a range starting
"9.6.0b1" (not a Go version). **All 73 are not affected on inspection**:
every range they name ends at or below 2.7.1 for torch 2.13.0, and at or
below 9.7.3 for go-redis 9.23.0. osv-scanner reports none of them. VulnScan
does not decide them, because deciding means assuming where a bound it
cannot read lies.

Read together: of 151 decided findings, 125 describe vulnerable code that
is there, and 26 match by version only. None is outright wrong, and
osv-scanner found nothing more.

**Two gaps that remain:** pip releases before 26.2 ship no SBOM, so
neither tool sees what they bundle (11 of the 24 environments). And
upgrading pip does not clear the bundled findings: 26.2.1, the newest pip
on 2026-10-09, still bundles urllib3 2.7.0 and msgpack 1.1.2.

## Secrets

One finding: a real Groq key in papertrail-rag's `.env`, **true**, and
correctly `uncommitted` (the file is git-ignored and was never committed),
so not failing. No committed secret in 298 commits (2,416 distinct file
versions) and 2,807 working-tree files. In 16 repositories iCloud had moved
HEAD or its branch's ref off the disk; HEAD was read from its reflog in all
16 (before Milestone 5's fix, those repositories' working-tree secrets
would have been called uncommitted). The false-positive measurement is in
the README ("On my portfolio"): it was made on this data and the bugs it
showed were fixed, so it is not independent.

## Dockerfiles and Compose files

49 findings in 20 files: 48 true, 1 false in context (a missing
HEALTHCHECK that LinkForge's Compose file provides). The details are in the
README. The ones that matter: LinkForge and PaperTrail publish Postgres on
every network interface with its user name as the password, and LinkForge
also publishes Redis.

## Scan time

`bench/scan_time.py`: one warm-up scan, then five interleaved passes over
five configurations, each run checked for swapping (none of the 50 runs
across the two measurements below swapped in more than 1.4 MB, so all are
valid). Warm: files in the operating system's cache. One 8 GB M2 laptop.

| Part | Median wall time (range) | CPU | Peak memory |
|---|---|---|---|
| Whole scan | **7.4 s** (7.4-7.8) | 6.3 s | 91 MB |
| Dependencies | 2.1 s (2.0-2.3) | 2.0 s | 42 MB |
| Secrets, all history | 5.8 s (5.7-6.1) | 4.8 s | 87 MB |
| Secrets, HEAD only | 4.6 s (4.5-4.8) | 3.8 s | 86 MB |
| Containers | 0.5 s (0.5-0.6) | 0.5 s | 38 MB |

(`bench/results/20261009T210529Z.json`.) The first measurement
(`20261009T210213Z.json`) gave a whole scan of 14.0 s, secrets 12.2 s; a
profile showed the twelve token-format patterns running over every file
took 57% of the secret scan. Each format needs a literal (`ghp_`, `AKIA`,
`T3BlbkFJ`...), so a format whose literal is not in a file is no longer
searched for: the same findings on the whole portfolio, byte for byte, in
half the time. The scan is CPU-bound once warm; the 12-50 s seen in
Milestone 4 were cold reads of an iCloud folder. An earlier run of the
measurement recorded CPU time as 0 (a parsing bug in the script); its file
was deleted rather than kept, and it was repeated (the four parts' wall
times it printed were within 0.2 s of the first measurement above; its
whole-scan time was not seen).

## What could not be read

- iCloud placeholders: 781 working-tree files (32 with a committed version,
  scanned from git), 6 Dockerfiles whose committed copies are placeholders
  too, files under `.git` in 17 repositories (45 objects in 7 of them).
- Not covered: R and Java dependencies, pips before 26.2 (no SBOM),
  C libraries listed in SBOMs.

## Fixes

Chosen by me (the roadmap: "fixes to the affected repos only where I
choose"), from four offered: closing the databases, upgrading pip in 11
environments, upgrading the other vulnerable libraries in their
environments, and updating LinkForge's test tooling. **I chose the first
only.**

- **LinkForge and PaperTrail publish their databases on localhost only**
  (`127.0.0.1:5432:5432`, and LinkForge's Redis `127.0.0.1:6379:6379`),
  as SurgiServe already did. Committed on a branch in each repository,
  `fix/compose-databases-localhost` (LinkForge 9ffdb67, PaperTrail
  183c496), not merged and not pushed. Checked: both files still pass
  `docker compose config`; VulnScan on each repository finds exactly the
  three `database-port-published` findings gone and nothing else changed;
  PaperTrail's tests pass (91; 4 that need the database were skipped,
  since Docker would not start that day). LinkForge's API tests need Docker
  too and were not run; the change touches only the Compose file and a
  README line. The default passwords stay: local development values, now
  reachable from this machine only.
- **Not changed, on purpose:** the dependency findings (pip, pypdf, urllib3,
  mako, multidict, accelerate, cryptography, LinkForge's Vitest), the
  Dockerfile findings, and the passwords.
