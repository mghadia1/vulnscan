"""A scan's result, and how it is written out: JSON for tools, text for people.

The JSON has a schema number; a change to its meaning raises it.
"""

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from vulnscan import __version__
from vulnscan.classify import Kind, classify
from vulnscan.inventory import Inventory, build
from vulnscan.walk import Tree

SCHEMA = 1


@dataclass(frozen=True)
class Finding:
    """One problem found. Filled in by later milestones."""

    rule: str
    severity: str
    path: str
    message: str


@dataclass(frozen=True)
class Report:
    target: str
    tree: Tree
    recognized: tuple[tuple[str, Kind], ...]
    inventory: Inventory
    findings: tuple[Finding, ...] = field(default=())

    @classmethod
    def from_tree(cls, target: str, tree: Tree) -> Report:
        recognized = tuple(
            (path, kind) for path in tree.files if (kind := classify(path)) is not None
        )
        return cls(
            target=target, tree=tree, recognized=recognized, inventory=build(tree)
        )

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

    def to_json(self) -> str:
        inv = self.inventory
        document = {
            "tool": {"name": "vulnscan", "version": __version__},
            "schema": SCHEMA,
            "target": self.target,
            "summary": {
                "files": len(self.tree.files),
                "recognized": len(self.recognized),
                "environments": len(self.tree.environments),
                "symlinks": len(self.tree.symlinks),
                "errors": len(self.tree.errors),
                "findings": len(self.findings),
            },
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
            "findings": [asdict(f) for f in self.findings],
        }
        return json.dumps(document, indent=2) + "\n"

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
        if self.findings:
            lines.append(f"{len(self.findings)} findings")
            for f in self.findings:
                lines.append(f"  {f.severity:<8} {f.rule} {f.path}: {f.message}")
        else:
            lines.append("no findings (no advisories are checked yet)")
        return "\n".join(lines) + "\n"
