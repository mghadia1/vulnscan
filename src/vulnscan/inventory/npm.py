"""npm dependencies: package-lock.json (lockfile versions 2 and 3), and a
package.json's ranges when there is no lockfile.

A version 2 or 3 lockfile lists every installed package under "packages",
keyed by where it is installed: "node_modules/a", or
"node_modules/a/node_modules/b" for a second copy nested under a. The key
"" is the project itself; keys without node_modules ("client") are the
project's own workspaces, and "link": true entries point at them. Those
are the project's own code, not packages from the registry.
"""

import json
import re

from vulnscan.inventory.model import Ecosystem, How, Package, Parsed, Problem

_DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
_EXACT = re.compile(r"^[=v]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_LOCAL_PREFIXES = ("file:", "link:", "workspace:", "git", "github:", "http:", "https:")


def _key_lines(text: str) -> dict[str, int]:
    """The line of each "key": { in the file, as npm prints it (one per line)."""
    lines: dict[str, int] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        match = re.match(r'\s*"([^"]+)":\s*\{', raw)
        if match and match[1] not in lines:
            lines[match[1]] = number
    return lines


def _name_from_key(key: str) -> str:
    """ "node_modules/@scope/a/node_modules/b" -> "b"."""
    return key.rsplit("node_modules/", 1)[1]


def parse_package_lock(text: str, path: str) -> Parsed:
    parsed = Parsed()
    try:
        data = json.loads(text)
    except ValueError as error:
        parsed.problems.append(Problem(path, None, f"not valid JSON: {error}"))
        return parsed
    if not isinstance(data, dict):
        parsed.problems.append(Problem(path, None, "not a lockfile (not an object)"))
        return parsed
    version = data.get("lockfileVersion")
    packages = data.get("packages")
    if version == 1 or (
        packages is None and isinstance(data.get("dependencies"), dict)
    ):
        parsed.problems.append(
            Problem(
                path,
                None,
                "lockfile version 1 (npm 6) is not read; npm 7 or later rewrites it",
            )
        )
        return parsed
    if not isinstance(packages, dict):
        parsed.problems.append(Problem(path, None, 'no "packages" object'))
        return parsed

    # Direct dependencies: what the project and its workspaces declare.
    declared: set[str] = set()
    for key, entry in packages.items():
        if isinstance(entry, dict) and "node_modules/" not in key:
            for field in _DEPENDENCY_FIELDS:
                deps = entry.get(field)
                if isinstance(deps, dict):
                    declared.update(str(name) for name in deps)

    lines = _key_lines(text)
    for key, entry in packages.items():
        if "node_modules/" not in key:
            continue  # the project itself, or one of its workspaces
        line = lines.get(key)
        if not isinstance(entry, dict):
            parsed.problems.append(Problem(path, line, f"{key} is not an object"))
            continue
        if entry.get("link") is True:
            continue  # a link to one of the project's workspaces
        name = entry.get("name")
        if not isinstance(name, str):
            name = _name_from_key(key)
        version_ = entry.get("version")
        if not isinstance(version_, str):
            parsed.problems.append(Problem(path, line, f"{key} has no version"))
            continue
        resolved = entry.get("resolved")
        local = isinstance(resolved, str) and resolved.startswith(
            ("file:", "git+", "git:", "github:")
        )
        if entry.get("dev") is True or entry.get("devOptional") is True:
            scope = "dev"
        elif entry.get("optional") is True:
            scope = "optional"
        else:
            scope = "runtime"
        parsed.packages.append(
            Package(
                ecosystem=Ecosystem.NPM,
                name=name,
                version=version_,
                how=How.LOCKED,
                path=path,
                line=line,
                # Installed at the top, and asked for by name: a direct one.
                direct=key == f"node_modules/{name}" and name in declared,
                scope=scope,
                local=local,
            )
        )
    return parsed


def parse_package_json(text: str, path: str) -> Parsed:
    """A package.json's declared ranges: read only when no lockfile covers it."""
    parsed = Parsed()
    try:
        data = json.loads(text)
    except ValueError as error:
        parsed.problems.append(Problem(path, None, f"not valid JSON: {error}"))
        return parsed
    if not isinstance(data, dict):
        parsed.problems.append(Problem(path, None, "not an object"))
        return parsed
    scopes = {
        "dependencies": "runtime",
        "devDependencies": "dev",
        "optionalDependencies": "optional",
        "peerDependencies": "runtime",
    }
    lines = _key_lines(text)
    for field, scope in scopes.items():
        deps = data.get(field)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                parsed.problems.append(Problem(path, None, f"{name}: not a range"))
                continue
            exact = _EXACT.fullmatch(spec)
            parsed.packages.append(
                Package(
                    ecosystem=Ecosystem.NPM,
                    name=str(name),
                    version=spec.lstrip("=v") if exact else None,
                    how=How.PINNED if exact else How.DECLARED,
                    path=path,
                    line=lines.get(field),
                    spec=None if exact else spec,
                    direct=True,
                    scope=scope,
                    local=spec.startswith(_LOCAL_PREFIXES)
                    or spec.startswith((".", "/")),
                )
            )
    return parsed
