"""A scan's result, and how it is written out: JSON for tools, SARIF for
code scanning, text for people.

The JSON has a schema number; a change to its meaning raises it (2: the
findings, with their advisories, severity, fix and acceptance).
"""

import json
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

from vulnscan import __version__
from vulnscan.advisories import Snapshot
from vulnscan.baseline import Applied
from vulnscan.classify import Kind, classify
from vulnscan.findings import SEVERITIES, Finding, Matching, severity_rank
from vulnscan.inventory import Inventory, build
from vulnscan.sarif import to_sarif
from vulnscan.walk import Tree

SCHEMA = 2
THRESHOLDS = ("low", "medium", "high", "critical", "never")


@dataclass(frozen=True)
class Checked:
    """What the advisory check did."""

    snapshots: tuple[Snapshot, ...]
    matching: Matching
    applied: Applied
    baseline: str | None  # the file the acceptances came from
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Report:
    target: str
    tree: Tree
    recognized: tuple[tuple[str, Kind], ...]
    inventory: Inventory
    checked: Checked | None = None  # None: --no-advisories
    threshold: str = "low"

    @classmethod
    def from_tree(cls, target: str, tree: Tree) -> Report:
        recognized = tuple(
            (path, kind) for path in tree.files if (kind := classify(path)) is not None
        )
        return cls(
            target=target, tree=tree, recognized=recognized, inventory=build(tree)
        )

    @property
    def findings(self) -> tuple[Finding, ...]:
        return self.checked.applied.findings if self.checked else ()

    def failing(self, finding: Finding) -> bool:
        """Fails the scan: decided, not accepted, at or above the threshold
        (an unknown severity is never below it)."""
        return (
            self.threshold != "never"
            and finding.certain
            and finding.accepted is None
            and severity_rank(finding.severity) >= severity_rank(self.threshold)
        )

    @property
    def failed(self) -> bool:
        return any(self.failing(f) for f in self.findings)

    @property
    def unchecked(self) -> dict[str, int]:
        return self.checked.matching.unchecked if self.checked else {}

    def _inventory_summary(self) -> dict[str, Any]:
        packages = self.inventory.packages
        return {
            "packages": len(packages),
            "by_ecosystem": dict(
                sorted(Counter(p.ecosystem for p in packages).items())
            ),
            "by_how": dict(sorted(Counter(p.how for p in packages).items())),
            "local": sum(p.local for p in packages),
        }

    def _finding(self, f: Finding) -> dict[str, Any]:
        p = f.package
        return {
            "rule": f.rule,
            "severity": f.severity,
            "score": f.score,
            "severity_source": f.severity_source,
            "vector": f.vector,
            "package": {
                "ecosystem": p.ecosystem,
                "name": p.name,
                "version": p.version,
                "how": p.how.value,
                "path": p.path,
                "line": p.line,
                "direct": p.direct,
                "scope": p.scope,
            },
            "advisories": list(f.advisories),
            "aliases": list(f.aliases),
            "summary": f.summary,
            "fixed_in": f.fixed_in,
            "fix": f.fix_note,
            "references": list(f.references),
            "certain": f.certain,
            "fingerprint": f.fingerprint,
            "accepted": (
                {"reason": f.accepted.reason, "expires": f.accepted.expires.isoformat()}
                if f.accepted
                else None
            ),
            "failing": self.failing(f),
        }

    def _summary(self) -> dict[str, Any]:
        findings = self.findings
        return {
            "files": len(self.tree.files),
            "recognized": len(self.recognized),
            "environments": len(self.tree.environments),
            "symlinks": len(self.tree.symlinks),
            "errors": len(self.tree.errors),
            "packages": len(self.inventory.packages),
            "findings": len(findings),
            "failing": sum(self.failing(f) for f in findings),
            "accepted": sum(f.accepted is not None for f in findings),
            "undecided": sum(not f.certain for f in findings),
            "by_severity": dict(
                sorted(
                    Counter(f.severity for f in findings if f.certain).items(),
                    key=lambda item: -severity_rank(item[0]),
                )
            ),
        }

    def to_json(self) -> str:
        inv = self.inventory
        c = self.checked
        document: dict[str, Any] = {
            "tool": {"name": "vulnscan", "version": __version__},
            "schema": SCHEMA,
            "target": self.target,
            "threshold": self.threshold,
            "summary": self._summary(),
            "files": [{"path": p, "kind": str(k)} for p, k in self.recognized],
            "environments": list(self.tree.environments),
            "symlinks": list(self.tree.symlinks),
            "skipped": list(self.tree.skipped),
            "errors": list(self.tree.errors),
            "inventory": {
                "summary": self._inventory_summary(),
                "environments": [asdict(e) for e in inv.environments],
                "packages": [
                    {k: v for k, v in asdict(p).items() if v is not None}
                    for p in inv.packages
                ],
                "problems": [asdict(p) for p in inv.problems],
                "not_read": [{"path": p, "why": why} for p, why in inv.not_read],
            },
            "advisories": (
                {
                    "checked": True,
                    "snapshots": [
                        {
                            "ecosystem": s.ecosystem,
                            "as_of": s.last_modified or s.built,
                            "sha256": s.sha256,
                            "advisories": s.advisories,
                        }
                        for s in c.snapshots
                    ],
                    "packages_checked": c.matching.checked,
                    "declared_only": c.matching.declared_only,
                    "local": c.matching.local,
                    "unchecked": c.matching.unchecked,
                    "notes": list(c.notes),
                }
                if c
                else {"checked": False}
            ),
            "findings": [self._finding(f) for f in self.findings],
            "baseline": (
                {
                    "file": c.baseline,
                    "expired": [
                        {
                            "advisory": a.advisory,
                            "package": a.package,
                            "expires": a.expires.isoformat(),
                            "reason": a.reason,
                            "finding": f.fingerprint,
                        }
                        for a, f in c.applied.expired
                    ],
                    "unused": [
                        {
                            "advisory": a.advisory,
                            "package": a.package,
                            "expires": a.expires.isoformat(),
                        }
                        for a in c.applied.unused
                    ],
                }
                if c
                else None
            ),
        }
        return json.dumps(document, indent=2) + "\n"

    def to_sarif(self) -> str:
        return json.dumps(to_sarif(self.findings), indent=2) + "\n"

    def to_text(self) -> str:
        t = self.tree
        inv = self.inventory
        summary = self._inventory_summary()
        lines = [
            f"vulnscan {__version__}: {self.target}",
            f"{len(t.files)} files, {len(self.recognized)} of them "
            f"manifests, lockfiles or container files; "
            f"{len(t.environments)} Python environments; "
            f"{len(t.symlinks)} links not followed",
        ]
        ecosystems = ", ".join(f"{k} {v}" for k, v in summary["by_ecosystem"].items())
        hows = ", ".join(f"{v} {k}" for k, v in summary["by_how"].items())
        line = f"{summary['packages']} packages"
        if summary["packages"]:
            line += f" ({ecosystems}): {hows}"
        if summary["local"]:
            line += f"; {summary['local']} local, not from a registry"
        lines.append(line)
        environments = {e.path for e in inv.environments}
        per_file = Counter(
            p.path
            for p in inv.packages
            if not any(p.path.startswith(env + "/") for env in environments)
        )
        for path, count in sorted(per_file.items()):
            lines.append(f"  {count:>5}  {path}")
        for env in inv.environments:
            python = f"Python {env.python}" if env.python else "Python unknown"
            lines.append(f"  {env.packages:>5}  {env.path} (installed, {python})")
        if inv.not_read:
            lines.append("not read:")
            lines += [f"  {path}: {why}" for path, why in inv.not_read]
        if inv.problems or t.errors:
            lines.append("problems:")
            lines += [f"  could not read {error}" for error in t.errors]
            lines += [
                f"  {p.path}{f':{p.line}' if p.line else ''}: {p.message}"
                for p in inv.problems
            ]
        lines += self._text_findings()
        return "\n".join(lines) + "\n"

    def _text_findings(self) -> list[str]:
        c = self.checked
        if c is None:
            return ["advisories not checked (--no-advisories)"]
        lines = []
        as_of = ", ".join(
            f"{s.ecosystem} {s.last_modified or s.built}" for s in c.snapshots
        )
        lines.append(
            f"advisories ({as_of}): {c.matching.checked} packages checked; "
            f"{c.matching.declared_only} known only as ranges and "
            f"{c.matching.local} local, not checked"
        )
        for ecosystem, count in c.matching.unchecked.items():
            lines.append(
                f"  NOT CHECKED: {count} {ecosystem} packages, no {ecosystem} "
                f"advisory data (vulnscan update --ecosystem {ecosystem})"
            )
        lines += [f"  note: {note}" for note in c.notes]

        decided = [f for f in self.findings if f.certain and f.accepted is None]
        accepted = [f for f in self.findings if f.accepted is not None]
        undecided = [f for f in self.findings if not f.certain]
        failing = sum(self.failing(f) for f in self.findings)
        threshold = (
            "never fails"
            if self.threshold == "never"
            else f"--fail-on {self.threshold}"
        )
        lines.append(f"{len(decided)} findings, {failing} failing ({threshold})")
        for f in decided:
            lines += self._finding_lines(f)
        if accepted:
            lines.append(f"{len(accepted)} accepted (not failing):")
            for f in accepted:
                assert f.accepted is not None
                lines += self._finding_lines(f)
                expires, reason = f.accepted.expires, f.accepted.reason
                lines.append(f"           accepted until {expires}: {reason}")
        if undecided:
            # Grouped by package version: one advisory with a malformed range
            # can stand for many places (every environment with torch, say).
            lines.append(f"{len(undecided)} could not be decided (not failing):")
            groups: dict[tuple[str, str, str], list[Finding]] = {}
            for f in undecided:
                p = f.package
                groups.setdefault((p.ecosystem, p.name, p.version or ""), []).append(f)
            for (ecosystem, name, version), members in groups.items():
                ids = sorted({f.advisories[0] for f in members})
                places = len({f.path for f in members})
                lines.append(
                    f"  {ecosystem} {name} {version} ({places} "
                    f"{'place' if places == 1 else 'places'}): {', '.join(ids)}"
                )
                for note in sorted({f.fix_note for f in members}):
                    lines.append(f"           {note}")
        for acceptance, finding in c.applied.expired:
            lines.append(
                f"  acceptance of {acceptance.advisory} expired {acceptance.expires} "
                f"({finding.title}): failing again"
            )
        for acceptance in c.applied.unused:
            lines.append(
                f"  acceptance of {acceptance.advisory} matches no finding "
                f"({c.baseline}): remove it?"
            )
        return lines

    def _finding_lines(self, f: Finding) -> list[str]:
        p = f.package
        score = f"{f.score:.1f}" if f.score is not None else "   "
        where = f"{p.path}{f':{p.line}' if p.line else ''}"
        names = f.advisories[0]
        others = [*f.advisories[1:], *f.aliases]
        if others:
            names += f" ({', '.join(others[:3])}{', ...' if len(others) > 3 else ''})"
        scope = f" [{p.scope}]" if p.scope and p.scope != "runtime" else ""
        return [
            f"  {f.severity.upper():<8} {score} "
            f"{p.ecosystem} {p.name} {p.version}{scope}  {where}",
            f"           {names}: {f.summary}",
            f"           {f.fix_note}",
        ]


__all__ = ["SEVERITIES", "THRESHOLDS", "Checked", "Report"]
