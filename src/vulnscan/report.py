"""A scan's result, and how it is written out: JSON for tools, SARIF for
code scanning, text for people.

The JSON has a schema number; a change to its meaning raises it (2: the
findings, with their advisories, severity, fix and acceptance; 3: secrets;
4: container findings).

No output contains a secret: a secret finding carries its rule, place,
redacted form (a fixed prefix at most, and the length) and fingerprint.
"""

import json
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

from vulnscan import __version__
from vulnscan.advisories import Snapshot
from vulnscan.baseline import Applied
from vulnscan.classify import Kind, classify
from vulnscan.containers import AppliedConfig, ConfigFinding, ContainerScan
from vulnscan.findings import SEVERITIES, Finding, Matching, severity_rank
from vulnscan.inventory import Inventory, build
from vulnscan.sarif import to_sarif
from vulnscan.secrets import AppliedSecrets, SecretFinding, SecretScan, commit_date
from vulnscan.walk import Tree

SCHEMA = 4
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
class SecretsChecked:
    """What the secret scan did."""

    scan: SecretScan
    applied: AppliedSecrets
    baseline: str | None


@dataclass(frozen=True)
class ContainersChecked:
    """What the Dockerfile and Compose checks did."""

    scan: ContainerScan
    applied: AppliedConfig
    baseline: str | None


@dataclass(frozen=True)
class Report:
    target: str
    tree: Tree
    recognized: tuple[tuple[str, Kind], ...]
    inventory: Inventory
    checked: Checked | None = None  # None: --no-advisories
    threshold: str = "low"
    secrets: SecretsChecked | None = None  # None: --no-secrets
    containers: ContainersChecked | None = None  # None: --no-containers

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
    def secret_findings(self) -> tuple[SecretFinding, ...]:
        return self.secrets.applied.findings if self.secrets else ()

    def failing_secret(self, finding: SecretFinding) -> bool:
        """As for advisories; a secret that is not committed never fails."""
        return (
            self.threshold != "never"
            and finding.state != "uncommitted"
            and finding.accepted is None
            and severity_rank(finding.severity) >= severity_rank(self.threshold)
        )

    @property
    def config_findings(self) -> tuple[ConfigFinding, ...]:
        return self.containers.applied.findings if self.containers else ()

    def failing_config(self, finding: ConfigFinding) -> bool:
        return (
            self.threshold != "never"
            and finding.accepted is None
            and severity_rank(finding.severity) >= severity_rank(self.threshold)
        )

    @property
    def failed(self) -> bool:
        return (
            any(self.failing(f) for f in self.findings)
            or any(self.failing_secret(f) for f in self.secret_findings)
            or any(self.failing_config(f) for f in self.config_findings)
        )

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
            "repositories": len(self.tree.repositories),
            "secrets": len(self.secret_findings),
            "secrets_failing": sum(
                self.failing_secret(f) for f in self.secret_findings
            ),
            "secrets_by_state": dict(
                Counter(f.state for f in self.secret_findings).most_common()
            ),
            "container_files": (
                len(self.containers.scan.files) if self.containers else 0
            ),
            "container_findings": len(self.config_findings),
            "container_failing": sum(
                self.failing_config(f) for f in self.config_findings
            ),
        }

    def _config(self, f: ConfigFinding) -> dict[str, Any]:
        return {
            "rule": f.rule,
            "title": f.title,
            "severity": f.severity,
            "path": f.path,
            "line": f.line,
            "subject": f.subject,
            "message": f.message,
            "fix": f.fix,
            "fingerprint": f.fingerprint,
            "read_from": f.source,
            "accepted": (
                {"reason": f.accepted.reason, "expires": f.accepted.expires.isoformat()}
                if f.accepted
                else None
            ),
            "failing": self.failing_config(f),
        }

    def _containers_json(self) -> dict[str, Any]:
        c = self.containers
        if c is None:
            return {"checked": False}
        return {
            "checked": True,
            "files": [
                {
                    "path": f.path,
                    "kind": f.kind,
                    "read_from": f.source,
                    "error": f.error,
                }
                for f in c.scan.files
            ],
            "findings": [self._config(f) for f in c.applied.findings],
            "baseline": {
                "file": c.baseline,
                "expired": [
                    {
                        "rule": a.rule,
                        "path": a.path,
                        "expires": a.expires.isoformat(),
                        "reason": a.reason,
                        "finding": f.fingerprint,
                    }
                    for a, f in c.applied.expired
                ],
                "unused": [
                    {"rule": a.rule, "path": a.path, "expires": a.expires.isoformat()}
                    for a in c.applied.unused
                ],
            },
        }

    def _secret(self, f: SecretFinding) -> dict[str, Any]:
        return {
            "rule": f.rule,
            "title": f.title,
            "severity": f.severity,
            "path": f.path,
            "line": f.line,
            "column": f.column,
            "shown": f.shown,
            "fingerprint": f.fingerprint,
            "state": f.state,
            "repository": f.repository,
            "commit": f.commit,
            "commit_date": commit_date(f),
            "pushed": f.pushed,
            "note": f.note,
            "advice": f.advice,
            "accepted": (
                {"reason": f.accepted.reason, "expires": f.accepted.expires.isoformat()}
                if f.accepted
                else None
            ),
            "failing": self.failing_secret(f),
        }

    def _secrets_json(self) -> dict[str, Any]:
        s = self.secrets
        if s is None:
            return {"checked": False}
        return {
            "checked": True,
            "history": "all refs" if s.scan.history else "HEAD only",
            "files_scanned": s.scan.files_scanned,
            "skipped": {
                "binary": s.scan.skipped_binary,
                "large": s.scan.skipped_large,
                "unreadable": list(s.scan.unreadable),
                "not_on_disk": [
                    {"path": path, "in_head": in_head}
                    for path, in_head in s.scan.offline
                ],
            },
            "repositories": [
                {
                    "path": r.path,
                    "head": r.head,
                    "commits": r.commits,
                    "blobs": r.blobs,
                    "missing_objects": r.missing,
                    "not_on_disk": r.offline,
                    "remotes": r.remotes,
                    "error": r.error,
                    "notes": list(r.notes),
                }
                for r in s.scan.repositories
            ],
            "findings": [self._secret(f) for f in s.applied.findings],
            "baseline": {
                "file": s.baseline,
                "expired": [
                    {
                        "secret": a.secret,
                        "expires": a.expires.isoformat(),
                        "reason": a.reason,
                        "path": f.path,
                    }
                    for a, f in s.applied.expired
                ],
                "unused": [
                    {"secret": a.secret, "expires": a.expires.isoformat()}
                    for a in s.applied.unused
                ],
            },
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
            "secrets": self._secrets_json(),
            "containers": self._containers_json(),
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
        sarif = to_sarif(self.findings, self.secret_findings, self.config_findings)
        return json.dumps(sarif, indent=2) + "\n"

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
        lines += self._text_secrets()
        lines += self._text_containers()
        return "\n".join(lines) + "\n"

    def _text_containers(self) -> list[str]:
        c = self.containers
        if c is None:
            return ["Dockerfiles and Compose files not checked (--no-containers)"]
        files = c.scan.files
        read = [f for f in files if f.source is not None]
        from_git = sum(f.source == "HEAD" for f in read)
        dockerfiles = sum(f.kind == "dockerfile" for f in read)
        lines = [
            f"containers: {dockerfiles} Dockerfiles and {len(read) - dockerfiles} "
            "Compose files read"
            + (f" ({from_git} from git's HEAD: not on this disk)" if from_git else "")
        ]
        lines += [f"  NOT READ: {f.path}: {f.error}" for f in files if f.source is None]
        live = [f for f in c.applied.findings if f.accepted is None]
        accepted = [f for f in c.applied.findings if f.accepted is not None]
        failing = sum(self.failing_config(f) for f in c.applied.findings)
        lines.append(f"{len(live)} container findings, {failing} failing")
        for f in live:
            lines += self._config_lines(f)
        if accepted:
            lines.append(f"{len(accepted)} accepted (not failing):")
            for f in accepted:
                assert f.accepted is not None
                lines += self._config_lines(f)
                lines.append(
                    f"           accepted until {f.accepted.expires}: "
                    f"{f.accepted.reason}"
                )
        for acceptance, finding in c.applied.expired:
            lines.append(
                f"  acceptance of {acceptance.rule} expired {acceptance.expires} "
                f"({finding.path}): failing again"
            )
        for acceptance in c.applied.unused:
            where = f" in {acceptance.path}" if acceptance.path else ""
            lines.append(
                f"  acceptance of {acceptance.rule}{where} matches no finding "
                f"({c.baseline}): remove it?"
            )
        return lines

    def _config_lines(self, f: ConfigFinding) -> list[str]:
        source = " (read from HEAD)" if f.source == "HEAD" else ""
        return [
            f"  {f.severity.upper():<8} {f.rule}  {f.path}:{f.line}{source}",
            f"           {f.message}",
            f"           fix: {f.fix}",
        ]

    def _text_secrets(self) -> list[str]:
        s = self.secrets
        if s is None:
            return ["secrets not checked (--no-secrets)"]
        scan = s.scan
        commits = sum(r.commits for r in scan.repositories)
        lines = [
            f"secrets: {scan.files_scanned} files and the history of "
            f"{len(scan.repositories)} git "
            f"{'repository' if len(scan.repositories) == 1 else 'repositories'} "
            f"({commits} commits, "
            f"{'all refs' if scan.history else 'HEAD only'}); "
            f"{scan.skipped_binary} binary and {scan.skipped_large} large "
            "files skipped"
        ]
        if scan.offline:
            in_head = sum(1 for _, h in scan.offline if h)
            lines.append(
                f"  {len(scan.offline)} files not on this disk (iCloud "
                f"placeholders) not read: {in_head} have a committed version, "
                f"scanned from git; {len(scan.offline) - in_head} not scanned"
            )
        for r in scan.repositories:
            if r.error:
                lines.append(f"  NOT READ: {r.path}/.git: {r.error}")
            if r.offline:
                lines.append(
                    f"  {r.path}: {r.offline} files under .git not on this disk "
                    "(iCloud) and not read: its history may be incomplete"
                )
            if r.missing:
                lines.append(
                    f"  {r.path}: {r.missing} objects missing or not on this disk"
                )
            lines += [f"  {r.path}: {note}" for note in r.notes]
        found = s.applied.findings
        live = [f for f in found if f.state != "uncommitted" and not f.accepted]
        accepted = [f for f in found if f.accepted is not None]
        local = [f for f in found if f.state == "uncommitted" and not f.accepted]
        failing = sum(self.failing_secret(f) for f in found)
        lines.append(f"{len(live)} secrets, {failing} failing")
        for f in live:
            lines += self._secret_lines(f)
        if accepted:
            lines.append(f"{len(accepted)} accepted (not failing):")
            for f in accepted:
                assert f.accepted is not None
                lines += self._secret_lines(f)
                lines.append(
                    f"           accepted until {f.accepted.expires}: "
                    f"{f.accepted.reason}"
                )
        if local:
            lines.append(f"{len(local)} in files not committed (not failing):")
            for f in local:
                lines += self._secret_lines(f)
        for acceptance, finding in s.applied.expired:
            lines.append(
                f"  acceptance of secret {acceptance.secret} expired "
                f"{acceptance.expires} ({finding.path}): failing again"
            )
        for acceptance in s.applied.unused:
            lines.append(
                f"  acceptance of secret {acceptance.secret} matches no finding "
                f"({s.baseline}): remove it?"
            )
        return lines

    def _secret_lines(self, f: SecretFinding) -> list[str]:
        where = {
            "committed": "in HEAD",
            "history": "in history only",
            "in-git": "in a commit (HEAD unknown)",
            "file": "in a file",
            "uncommitted": "not committed",
        }[f.state]
        if f.commit:
            where += f", first in {f.commit[:10]} ({commit_date(f)})"
        note = f"; {f.note}" if f.note else ""
        return [
            f"  {f.severity.upper():<8} {f.rule}  {f.path}:{f.line}:{f.column}",
            f"           {f.shown}{note}; {where}; fingerprint {f.fingerprint}",
            f"           {f.advice}",
        ]

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
