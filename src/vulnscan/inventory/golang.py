"""Go dependencies: go.mod.

Since Go 1.17 a module's go.mod lists every module its build needs, the
ones only its dependencies use marked "// indirect", so go.mod alone is the
inventory. go.sum is not read: it also holds checksums of modules needed
only to read other go.mod files, which are never built.

The standard library is a dependency too, and has advisories of its own
(under the name "stdlib"). Which version builds the module is the
toolchain's: a "toolchain go1.27.1" line pins it; otherwise "go 1.27"
only sets the oldest Go that may, so it is reported as a range.
"""

import re

from vulnscan.inventory.model import Ecosystem, How, Package, Parsed, Problem


def _words(line: str) -> list[str]:
    """A line's words, with "quoted" module paths unquoted."""
    return [w.strip('"') for w in re.findall(r'"[^"]*"|\S+', line)]


def parse_go_mod(text: str, path: str) -> Parsed:
    parsed = Parsed()
    requires: list[tuple[int, str, str, bool]] = []  # line, module, version, direct
    replaces: dict[tuple[str, str | None], tuple[str, str | None]] = {}
    go_version: str | None = None
    toolchain: tuple[int, str] | None = None
    go_line: int | None = None
    block: str | None = None

    for number, raw in enumerate(text.splitlines(), start=1):
        code, _, comment = raw.partition("//")
        indirect = comment.strip() == "indirect" or comment.strip().startswith(
            "indirect;"
        )
        words = _words(code)
        if not words:
            continue
        if block is not None:
            if words == [")"]:
                block = None
                continue
            verb, args = block, words
        elif len(words) >= 2 and words[1] == "(" and len(words) == 2:
            block = words[0]
            continue
        else:
            verb, args = words[0], words[1:]

        if verb == "go" and args:
            go_version, go_line = args[0], number
        elif verb == "toolchain" and args:
            toolchain = (number, args[0])
        elif verb == "require":
            if len(args) != 2:
                parsed.problems.append(
                    Problem(
                        path,
                        number,
                        f"a require that is not 'module version': {raw.strip()}",
                    )
                )
                continue
            requires.append((number, args[0], args[1], not indirect))
        elif verb == "replace":
            if "=>" not in args:
                parsed.problems.append(Problem(path, number, "a replace without =>"))
                continue
            at = args.index("=>")
            old, new = args[:at], args[at + 1 :]
            if len(old) not in (1, 2) or len(new) not in (1, 2):
                parsed.problems.append(Problem(path, number, "a malformed replace"))
                continue
            replaces[(old[0], old[1] if len(old) == 2 else None)] = (
                new[0],
                new[1] if len(new) == 2 else None,
            )

    for number, module, version, direct in requires:
        target = replaces.get((module, version)) or replaces.get((module, None))
        local = False
        if target is not None:
            new_module, new_version = target
            if new_version is None:
                # Only a folder replaces a module without a version: the
                # build uses local code under the module's own name.
                local = True
            else:
                module, version = new_module, new_version
        parsed.packages.append(
            Package(
                ecosystem=Ecosystem.GO,
                name=module,
                version=version,
                how=How.LOCKED,
                path=path,
                line=number,
                direct=direct,
                local=local,
            )
        )

    if toolchain is not None:
        number, name = toolchain
        if name.startswith("go"):
            parsed.packages.append(
                Package(
                    ecosystem=Ecosystem.GO,
                    name="stdlib",
                    version=name[2:].split("+", 1)[0],
                    how=How.PINNED,
                    path=path,
                    line=number,
                    direct=True,
                )
            )
    elif go_version is not None:
        parsed.packages.append(
            Package(
                ecosystem=Ecosystem.GO,
                name="stdlib",
                version=None,
                how=How.DECLARED,
                path=path,
                line=go_line,
                spec=f">={go_version}",
                direct=True,
            )
        )
    return parsed
