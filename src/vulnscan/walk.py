"""Which files of a repository a scan reads.

A scan reads the target directory and nothing outside it. Symbolic links
are recorded, never followed: a link in a repository can point anywhere on
the machine. Nothing is ever written. Directories that hold other people's
code or caches are skipped (``SKIPPED_DIRS``), and so is any Python virtual
environment, found by its ``pyvenv.cfg`` rather than by its name: its
installed packages are read separately, by the inventory.
"""

import os
from dataclasses import dataclass
from pathlib import Path

# Never walked into: version control, installed packages, caches.
SKIPPED_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".hypothesis",
        ".tox",
        ".nox",
    }
)

# A directory holding this file is a Python virtual environment.
VENV_MARKER = "pyvenv.cfg"


@dataclass(frozen=True)
class Tree:
    """What a walk found. Paths are relative to the root, with "/", sorted."""

    root: Path
    files: tuple[str, ...]
    environments: tuple[str, ...]
    symlinks: tuple[str, ...]
    skipped: tuple[str, ...]
    errors: tuple[str, ...]


def _relative(root: Path, path: str) -> str:
    return Path(path).relative_to(root).as_posix()


def walk(root: Path) -> Tree:
    """Walks ``root`` (a directory), without following links or writing."""
    files: list[str] = []
    environments: list[str] = []
    symlinks: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []

    def failed(error: OSError) -> None:
        where = error.filename if isinstance(error.filename, str) else str(root)
        errors.append(f"{_relative(root, where) or '.'}: {error.strerror}")

    for here, dirs, names in os.walk(root, onerror=failed, followlinks=False):
        kept: list[str] = []
        for name in sorted(dirs):
            path = os.path.join(here, name)
            if os.path.islink(path):
                symlinks.append(_relative(root, path))
            elif name in SKIPPED_DIRS:
                skipped.append(_relative(root, path))
            elif os.path.isfile(os.path.join(path, VENV_MARKER)):
                environments.append(_relative(root, path))
            else:
                kept.append(name)
        # Pruning in place is how os.walk is told not to descend.
        dirs[:] = kept
        for name in names:
            path = os.path.join(here, name)
            if os.path.islink(path):
                symlinks.append(_relative(root, path))
            else:
                files.append(_relative(root, path))

    return Tree(
        root=root,
        files=tuple(sorted(files)),
        environments=tuple(sorted(environments)),
        symlinks=tuple(sorted(symlinks)),
        skipped=tuple(sorted(skipped)),
        errors=tuple(sorted(errors)),
    )
