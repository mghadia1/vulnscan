"""Checks the inventory against the ecosystems' own tools, on real repositories.

    PYTHONPATH=src python scripts/check_inventory.py ../

For every Python environment, compares what VulnScan read with what that
environment's own ``pip list`` says; for every package-lock.json, with
``npm ls --all --package-lock-only``; for every go.mod, with
``go mod edit -json``. Prints each difference and a total. Needs pip in
each environment, npm 7+ and Go on the PATH (a missing tool is reported
and its files skipped). The tools are used here only to check against;
VulnScan never runs them.
"""

import json
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from vulnscan.inventory import build
from vulnscan.inventory.model import Ecosystem
from vulnscan.inventory.pep508 import normalize
from vulnscan.walk import walk

Pairs = set[tuple[str, str]]


def run(command: list[str], cwd: Path) -> str | None:
    try:
        done = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=120, check=False
        )
    except OSError, subprocess.TimeoutExpired:
        return None
    # npm ls exits 1 for problems it reports in its JSON (missing optional
    # dependencies, say); the JSON is still the answer.
    return done.stdout if done.stdout.strip() else None


def npm_tree(node: dict[str, Any], skip: set[str]) -> Iterator[tuple[str, str]]:
    for name, child in (node.get("dependencies") or {}).items():
        if isinstance(child, dict):
            version = child.get("version")
            if isinstance(version, str) and name not in skip:
                yield name, version
            yield from npm_tree(child, skip)


def npm_workspaces(root: dict[str, Any]) -> set[str]:
    """The project's own workspaces: "file:" folders at the top (nested
    mentions of them carry no "resolved" at all)."""
    return {
        name
        for name, child in (root.get("dependencies") or {}).items()
        if isinstance(child, dict)
        and str(child.get("resolved", "")).startswith("file:")
    }


def compare(label: str, ours: Pairs, theirs: Pairs) -> bool:
    if ours == theirs:
        print(f"same      {label}: {len(ours)}")
        return True
    print(f"DIFFERENT {label}: ours {len(ours)}, theirs {len(theirs)}")
    for name, version in sorted(ours - theirs)[:10]:
        print(f"  only ours:   {name} {version}")
    for name, version in sorted(theirs - ours)[:10]:
        print(f"  only theirs: {name} {version}")
    return False


def main(top: Path) -> int:
    top = top.resolve()
    inv = build(walk(top))
    checked = differing = skipped = 0

    for env in inv.environments:
        ours = {
            (p.name, p.version or "")
            for p in inv.packages
            if p.path.startswith(env.path + "/")
        }
        out = run(
            [
                str(top / env.path / "bin/python"),
                "-m",
                "pip",
                "list",
                "--format",
                "json",
            ],
            top,
        )
        if out is None:
            print(f"skipped   {env.path}: its pip did not answer")
            skipped += 1
            continue
        theirs = {(normalize(d["name"]), d["version"]) for d in json.loads(out)}
        checked += 1
        differing += not compare(env.path, ours, theirs)

    for lock in sorted(
        {p.path for p in inv.packages if p.path.endswith("package-lock.json")}
    ):
        ours = {
            (p.name, p.version or "")
            for p in inv.packages
            if p.path == lock and p.ecosystem is Ecosystem.NPM
        }
        folder = (top / lock).parent
        out = run(["npm", "ls", "--all", "--json", "--package-lock-only"], folder)
        if out is None:
            print(f"skipped   {lock}: npm did not answer")
            skipped += 1
            continue
        checked += 1
        tree = json.loads(out)
        differing += not compare(lock, ours, set(npm_tree(tree, npm_workspaces(tree))))

    for mod in sorted({p.path for p in inv.packages if p.path.endswith("go.mod")}):
        ours = {
            (p.name, p.version or "")
            for p in inv.packages
            if p.path == mod and p.name != "stdlib"
        }
        out = run(["go", "mod", "edit", "-json"], (top / mod).parent)
        if out is None:
            print(f"skipped   {mod}: go did not answer")
            skipped += 1
            continue
        data = json.loads(out)
        replaced = {
            (r["Old"]["Path"], r["Old"].get("Version")): r["New"]
            for r in data.get("Replace") or []
        }
        theirs: Pairs = set()
        for r in data.get("Require") or []:
            new = replaced.get((r["Path"], r["Version"])) or replaced.get(
                (r["Path"], None)
            )
            if new is not None and new.get("Version"):
                theirs.add((new["Path"], new["Version"]))
            else:
                theirs.add((r["Path"], r["Version"]))
        checked += 1
        differing += not compare(mod, ours, theirs)

    print(f"{checked} checked, {differing} different, {skipped} skipped")
    return 1 if differing else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else ".")))
