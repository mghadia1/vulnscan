"""Findings: inventory packages matched to advisories.

One finding per package occurrence (a package at one version, found in one
file) and per vulnerability: advisories that are aliases of each other
(GO-2024-2687 and GHSA-4v7x-pqxf-cx7m, the same bug in the Go database
and GitHub's) are one finding, listing every id.

Severity: the highest CVSS 3.x base score among the advisories, computed
here from their vectors (``cvss.py``). An advisory with only a CVSS 4.0
vector, or none, falls back to its source's own word (GitHub's LOW,
MODERATE, HIGH, CRITICAL), and the finding says so. A malicious package
(OSV's MAL- advisories) is critical by definition: it was published to do
harm. Anything else is "unknown", which never passes as harmless.

The fix: the lowest version that fixes every advisory of the finding,
from the ranges' "fixed" events above the version found.

Not matched: local packages (the project's own code), and packages known
only by a declared range (which version is used is not known; most such
projects have an environment or lockfile that says).
"""

import hashlib
from dataclasses import dataclass, field
from datetime import date

from vulnscan.advisories import Database, lookup
from vulnscan.advisories.osv import Advisory, Affected, Verdict
from vulnscan.cvss import base_score, rating
from vulnscan.inventory import Inventory, Package
from vulnscan.versions import order

SEVERITIES = ("none", "low", "medium", "high", "critical")
_GITHUB_WORDS = {
    "LOW": "low",
    "MODERATE": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}
# Which id names a finding, of those it has: the most widely linked first.
_ID_PREFERENCE = ("GHSA-", "PYSEC-", "GO-", "MAL-")


def severity_rank(severity: str) -> int:
    """0 for none up to 4 for critical; "unknown" ranks above all, so that
    it can never pass a threshold for being harmless."""
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


@dataclass(frozen=True)
class Acceptance:
    """A finding accepted on purpose, in the baseline file (baseline.py):
    an advisory, a secret by its fingerprint, or a container rule (in one
    file, or everywhere)."""

    advisory: str | None
    package: str | None
    reason: str
    expires: date
    secret: str | None = None
    rule: str | None = None
    path: str | None = None


@dataclass(frozen=True)
class Finding:
    rule: str  # vulnerable-dependency, malicious-package, possibly-vulnerable
    severity: str  # none ... critical, or unknown
    score: float | None
    severity_source: str
    package: Package
    advisories: tuple[str, ...]  # the finding's own ids, the preferred one first
    aliases: tuple[str, ...]  # other names (CVE ids)
    summary: str
    fixed_in: str | None
    fix_note: str
    vector: str | None
    references: tuple[str, ...]
    certain: (
        bool  # False: some advisory could not be decided (rule possibly-vulnerable)
    )
    fingerprint: str
    accepted: Acceptance | None = field(default=None)

    @property
    def path(self) -> str:
        return self.package.path

    @property
    def ids(self) -> frozenset[str]:
        return frozenset(i.upper() for i in (*self.advisories, *self.aliases))

    @property
    def title(self) -> str:
        p = self.package
        return f"{p.ecosystem} {p.name} {p.version}: {self.advisories[0]}"


@dataclass(frozen=True)
class Matching:
    findings: tuple[Finding, ...]
    checked: int  # package occurrences looked up
    declared_only: int  # not looked up: no exact version known
    local: int  # not looked up: the project's own code
    unchecked: dict[str, int]  # ecosystem -> occurrences with no advisory data


def _fix(version: str, affected: Affected) -> tuple[str | None, bool]:
    """The lowest "fixed" above ``version`` in a range that affects it; and
    whether the advisory says anything about a fix at all."""
    best: tuple[tuple[object, ...], str] | None = None
    said = False
    for range_ in affected.ranges:
        order_ = order(affected.ecosystem, affected.name, range_.type)
        if order_ is None:
            continue
        current = order_(version)
        if current is None:
            continue
        for kind, text in range_.events:
            if kind != "fixed":
                continue
            said = True
            key = order_(text)
            if key is not None and key > current and (best is None or key < best[0]):
                best = (key, text)
    return (best[1] if best else None), said


def undecided_reason(version: str, affected: Affected) -> str:
    """Why an advisory could not be decided for this version, in words."""
    for range_ in affected.ranges:
        if range_.type == "GIT":
            if not affected.versions:
                return "the advisory gives only git commits, and no list of versions"
            continue
        order_ = order(affected.ecosystem, affected.name, range_.type)
        if order_ is None:
            return f"{range_.type} ranges cannot be compared for {affected.ecosystem}"
        if order_(version) is None:
            return f"{version} is not a version {affected.ecosystem}'s ordering reads"
        for kind, text in range_.events:
            special = (kind, text) in (("introduced", "0"), ("limit", "*"))
            if not special and order_(text) is None:
                return f'the advisory\'s own range uses "{text}", not a valid version'
    return "the advisory could not be compared with this version"


def _preferred(ids: set[str]) -> list[str]:
    def rank(i: str) -> tuple[int, str]:
        for n, prefix in enumerate(_ID_PREFERENCE):
            if i.startswith(prefix):
                return n, i
        return len(_ID_PREFERENCE), i

    return sorted(ids, key=rank)


def _groups(
    matches: list[tuple[Advisory, Verdict]],
) -> list[list[tuple[Advisory, Verdict]]]:
    """Advisories sharing an id or alias, together (the alias graph's parts)."""
    groups: list[tuple[set[str], list[tuple[Advisory, Verdict]]]] = []
    for advisory, verdict in matches:
        names = {advisory.id, *advisory.aliases}
        joined = [g for g in groups if g[0] & names]
        for g in joined:
            groups.remove(g)
            names |= g[0]
        members = [m for g in joined for m in g[1]] + [(advisory, verdict)]
        groups.append((names, members))
    return [members for _, members in groups]


def _severity(advisories: list[Advisory]) -> tuple[str, float | None, str, str | None]:
    if any(a.malicious for a in advisories):
        return "critical", None, "a malicious package", None
    best: tuple[float, str] | None = None
    for advisory in advisories:
        for kind, vector in advisory.severity:
            if kind in ("CVSS_V3", "CVSS_V31", "CVSS_V30"):
                scored = base_score(vector)
                if scored is not None and (best is None or scored.score > best[0]):
                    best = (scored.score, vector)
    if best is not None:
        return (
            rating(best[0]),
            best[0],
            "CVSS 3 base score, computed from the vector",
            best[1],
        )
    words = [
        _GITHUB_WORDS[a.database_severity]
        for a in advisories
        if a.database_severity in _GITHUB_WORDS
    ]
    if words:
        word = max(words, key=severity_rank)
        return (
            word,
            None,
            "GitHub's rating (no CVSS 3 vector; CVSS 4.0 is not scored here)",
            None,
        )
    return "unknown", None, "no severity given", None


_DISPLAY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "none": 5}


def display_order(f: Finding) -> tuple[object, ...]:
    """Decided findings first, worst first; then by package and place."""
    p = f.package
    return (
        not f.certain,
        _DISPLAY[f.severity],
        p.ecosystem,
        p.name,
        p.version or "",
        p.path,
    )


def finding_for(package: Package, group: list[tuple[Advisory, Verdict]]) -> Finding:
    version = package.version or ""
    advisories = [a for a, _ in group]
    certain = any(v is Verdict.AFFECTED for _, v in group)
    own = _preferred({a.id for a in advisories})
    aliases = sorted({x for a in advisories for x in a.aliases} - set(own))
    severity, score, source, vector = _severity(advisories)
    fixes: list[str] = []
    unfixed = False
    for advisory, verdict in group:
        if verdict is not Verdict.AFFECTED:
            continue
        fixed, said = _fix(version, advisory.affected[0])
        if fixed is not None:
            fixes.append(fixed)
        elif not said:
            unfixed = True
    order_ = order(package.ecosystem, package.name)
    fixed_in = (
        max(fixes, key=lambda v: (order_(v) or ()) if order_ else ()) if fixes else None
    )
    if any(a.malicious for a in advisories):
        rule, note = "malicious-package", "remove it: it was published to do harm"
    elif not certain:
        rule = "possibly-vulnerable"
        note = "could not be decided: " + undecided_reason(
            version, advisories[0].affected[0]
        )
    else:
        rule = "vulnerable-dependency"
        if fixed_in and not unfixed:
            note = f"upgrade to {fixed_in} or later"
        elif fixed_in:
            note = f"upgrade to {fixed_in} or later (one advisory names no fix)"
        else:
            note = "no fixed version has been published"
        scope = package.scope or ""
        if scope.startswith("bundled in "):
            # A copy inside another package: that package is what to upgrade.
            bundler = scope.removeprefix("bundled in ")
            note = (
                f"{scope}: upgrade {bundler} to a release that bundles "
                f"{package.name} {fixed_in} or later"
                if fixed_in
                else f"{scope}: {note}"
            )
    summary = next(
        (
            a.summary
            for a in sorted(advisories, key=lambda a: own.index(a.id))
            if a.summary
        ),
        "",
    )
    references: list[str] = []
    for advisory in advisories:
        references += [r for r in advisory.references if r not in references]
    key = "|".join(
        [rule, package.ecosystem, package.name, version, own[0], package.path]
    )
    return Finding(
        rule=rule,
        severity=severity,
        score=score,
        severity_source=source,
        package=package,
        advisories=tuple(own),
        aliases=tuple(aliases),
        summary=summary,
        fixed_in=fixed_in,
        fix_note=note,
        vector=vector,
        references=tuple(references[:5]),
        certain=certain,
        fingerprint=hashlib.sha256(key.encode()).hexdigest()[:16],
    )


def match(inventory: Inventory, db: Database) -> Matching:
    indexed = {s.ecosystem for s in db.snapshots()}
    findings: list[Finding] = []
    checked = declared = local = 0
    unchecked: dict[str, int] = {}
    for package in inventory.packages:
        if package.local:
            local += 1
            continue
        if package.version is None:
            declared += 1
            continue
        if package.ecosystem not in indexed:
            unchecked[package.ecosystem] = unchecked.get(package.ecosystem, 0) + 1
            continue
        checked += 1
        matches = [
            (m.advisory, m.verdict)
            for m in lookup(db, package.ecosystem, package.name, package.version)
        ]
        for group in _groups(matches):
            findings.append(finding_for(package, group))
    findings.sort(key=display_order)
    return Matching(tuple(findings), checked, declared, local, unchecked)
