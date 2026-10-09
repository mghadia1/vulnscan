"""A scan's result, and how it is written out: JSON for tools, text for people.

The JSON has a schema number; a change to its meaning raises it.
"""

import json
from dataclasses import dataclass, field

from vulnscan import __version__
from vulnscan.classify import Kind, classify
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
    findings: tuple[Finding, ...] = field(default=())

    @classmethod
    def from_tree(cls, target: str, tree: Tree) -> Report:
        recognized = tuple(
            (path, kind) for path in tree.files if (kind := classify(path)) is not None
        )
        return cls(target=target, tree=tree, recognized=recognized)

    def to_json(self) -> str:
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
            "findings": [
                {
                    "rule": f.rule,
                    "severity": f.severity,
                    "path": f.path,
                    "message": f.message,
                }
                for f in self.findings
            ],
        }
        return json.dumps(document, indent=2) + "\n"

    def to_text(self) -> str:
        t = self.tree
        lines = [
            f"vulnscan {__version__}: {self.target}",
            f"{len(t.files)} files, {len(self.recognized)} of them "
            f"manifests, lockfiles or container files; "
            f"{len(t.environments)} Python environments; "
            f"{len(t.symlinks)} links not followed",
        ]
        for path, kind in self.recognized:
            lines.append(f"  {kind:<13} {path}")
        for env in t.environments:
            lines.append(f"  {'environment':<13} {env}")
        for error in t.errors:
            lines.append(f"  could not read {error}")
        if self.findings:
            lines.append(f"{len(self.findings)} findings")
            for f in self.findings:
                lines.append(f"  {f.severity:<8} {f.rule} {f.path}: {f.message}")
        else:
            lines.append("no findings (nothing is checked yet: Milestone 0)")
        return "\n".join(lines) + "\n"
