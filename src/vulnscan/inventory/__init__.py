"""The inventory: exactly what a repository depends on, and how sure that is.

Each recognised file goes to its reader; every installed environment is
read too. A file that is recognised but not read says why (``not_read``),
and anything a reader could not make sense of is a problem, reported with
its file and line, never a crash.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from vulnscan.classify import Kind, classify
from vulnscan.inventory.golang import parse_go_mod
from vulnscan.inventory.model import Ecosystem, How, Package, Parsed, Problem
from vulnscan.inventory.npm import parse_package_json, parse_package_lock
from vulnscan.inventory.python import (
    parse_poetry_lock,
    parse_pyproject,
    parse_requirements,
    parse_uv_lock,
    python_version,
    read_environment,
)
from vulnscan.walk import Tree

__all__ = [
    "Ecosystem",
    "Environment",
    "How",
    "Inventory",
    "Package",
    "Problem",
    "build",
]

# Larger than any real lockfile; a file over it is reported, not read.
MAX_BYTES = 50 * 1024 * 1024

Reader = Callable[[str, str], Parsed]

READERS: dict[Kind, Reader] = {
    Kind.REQUIREMENTS: parse_requirements,
    Kind.PYPROJECT: parse_pyproject,
    Kind.UV_LOCK: parse_uv_lock,
    Kind.POETRY_LOCK: parse_poetry_lock,
    Kind.NPM_LOCK: parse_package_lock,
    Kind.GO_MOD: parse_go_mod,
}

NOT_READ: dict[Kind, str] = {
    Kind.GO_SUM: "go.mod lists every module the build needs",
    Kind.PIPFILE_LOCK: "Pipfile.lock is not read yet",
    Kind.YARN_LOCK: "yarn.lock is not read yet",
    Kind.PNPM_LOCK: "pnpm-lock.yaml is not read yet",
    Kind.MAVEN_POM: "Java (Maven) dependencies are not covered",
    Kind.GRADLE: "Java (Gradle) dependencies are not covered",
    Kind.RENV_LOCK: "R (CRAN) dependencies are not covered",
    Kind.CARGO_LOCK: "Rust dependencies are not covered",
    Kind.DOCKERFILE: "container rules come in Milestone 5",
    Kind.COMPOSE: "container rules come in Milestone 5",
}


@dataclass(frozen=True)
class Environment:
    path: str
    python: str | None
    packages: int


@dataclass(frozen=True)
class Inventory:
    packages: tuple[Package, ...]
    problems: tuple[Problem, ...]
    not_read: tuple[tuple[str, str], ...]  # (path, why)
    environments: tuple[Environment, ...]


def _read_text(root: Path, path: str, problems: list[Problem]) -> str | None:
    file = root / path
    try:
        if file.stat().st_size > MAX_BYTES:
            problems.append(Problem(path, None, "larger than 50 MB; not read"))
            return None
        return file.read_bytes().decode("utf-8")
    except OSError as error:
        problems.append(Problem(path, None, f"unreadable: {error.strerror}"))
    except UnicodeDecodeError:
        problems.append(Problem(path, None, "not UTF-8; not read"))
    return None


def _npm_lock_above(path: str, locks: set[str]) -> str | None:
    """The npm lockfile in the same folder as ``path`` or a folder above it."""
    folder = PurePosixPath(path).parent
    for candidate in (folder, *folder.parents):
        for name in ("package-lock.json", "npm-shrinkwrap.json"):
            lock = (candidate / name).as_posix()
            if lock in locks:
                return lock
    return None


def build(tree: Tree) -> Inventory:
    root = tree.root
    packages: list[Package] = []
    problems: list[Problem] = []
    not_read: list[tuple[str, str]] = []
    files = set(tree.files)
    kinds = {path: kind for path in tree.files if (kind := classify(path))}
    npm_locks = {p for p, k in kinds.items() if k is Kind.NPM_LOCK}

    queue: list[tuple[str, Kind]] = sorted(kinds.items())
    done: set[str] = set()
    while queue:
        path, kind = queue.pop(0)
        if path in done:
            continue
        done.add(path)
        if kind is Kind.NPM_MANIFEST:
            lock = _npm_lock_above(path, npm_locks)
            if lock is not None:
                not_read.append((path, f"covered by {lock}"))
                continue
            reader: Reader = parse_package_json
        elif kind in READERS:
            reader = READERS[kind]
        else:
            not_read.append((path, NOT_READ[kind]))
            continue
        text = _read_text(root, path, problems)
        if text is None:
            continue
        parsed = reader(text, path)
        packages += parsed.packages
        problems += parsed.problems
        for include in parsed.includes:
            target = _inside(PurePosixPath(path).parent / include)
            # Only a file the walk saw: inside the target, not through a link.
            if target is None or target not in files:
                problems.append(
                    Problem(path, None, f"includes {include}, not found in the target")
                )
            elif target not in done:
                queue.append((target, Kind.REQUIREMENTS))

    environments: list[Environment] = []
    for env in tree.environments:
        parsed = read_environment(root, env)
        packages += parsed.packages
        problems += parsed.problems
        environments.append(
            Environment(env, python_version(root, env), len(parsed.packages))
        )

    packages.sort(key=lambda p: (p.path, p.line or 0, p.ecosystem, p.name))
    return Inventory(
        packages=tuple(packages),
        problems=tuple(problems),
        not_read=tuple(sorted(not_read)),
        environments=tuple(environments),
    )


def _inside(path: PurePosixPath) -> str | None:
    """A relative path with ".." resolved, or None if it climbs out."""
    if path.is_absolute():
        return None
    parts: list[str] = []
    for part in path.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts) if parts else None
