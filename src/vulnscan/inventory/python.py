"""Python dependencies: requirements files, pyproject.toml, uv.lock,
poetry.lock, and the packages installed in a virtual environment.

An environment is the surest source: it is what actually runs. Most of the
projects this was built for declare only lower bounds (``fastapi>=0.142``)
and have no lockfile, so without their environments the exact versions
would not be known at all.
"""

import json
import os
import re
import stat
import tomllib
from collections.abc import Callable
from email.parser import HeaderParser
from pathlib import Path
from typing import Any

from vulnscan.git import on_disk
from vulnscan.inventory import pep508, sbom
from vulnscan.inventory.model import Ecosystem, How, Package, Parsed, Problem

# requirements-file options that take a value and install nothing by
# themselves; the value is skipped.
_OPTIONS_WITH_VALUE = {
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "--trusted-host",
    "--no-binary",
    "--only-binary",
    "--use-feature",
}
_FLAGS = {"--pre", "--prefer-binary", "--require-hashes", "--no-index"}


_COMMENT = re.compile(r"(^|\s+)#.*$")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Lines as pip reads them, in pip's order: continuations ("\\" at the
    end) joined first, then comments removed ("#" at the start or after
    whitespace; a "#" inside a URL is not one). So in "pkg==1.0  # why \\"
    the next line becomes part of the comment, as it does for pip. (The
    first version removed comments first; a generated file showed it.)
    Each line keeps the number of its first physical line."""
    joined: list[tuple[int, str]] = []
    start = 0
    buffer: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        comment = _COMMENT.match(line) is not None
        if not line.endswith("\\") or comment:
            if buffer:
                buffer.append(" " + line if comment else line)
                joined.append((start, "".join(buffer)))
                buffer = []
            else:
                joined.append((number, line))
        else:
            if not buffer:
                start = number
            buffer.append(line.strip("\\"))
    if buffer:
        joined.append((start, "".join(buffer)))
    lines: list[tuple[int, str]] = []
    for number, line in joined:
        line = _COMMENT.sub("", line).strip()
        if line:
            lines.append((number, line))
    return lines


def _python_package(
    req: pep508.Requirement, path: str, line: int | None, **fields: Any
) -> Package:
    pinned = req.pinned
    return Package(
        ecosystem=Ecosystem.PYPI,
        name=req.normalized,
        version=pinned,
        how=How.PINNED if pinned is not None else How.DECLARED,
        path=path,
        line=line,
        spec=None if pinned is not None else req.spec,
        marker=req.marker,
        # A direct URL is not a registry release.
        local=req.url is not None,
        **fields,
    )


def parse_requirements(text: str, path: str) -> Parsed:
    """A pip requirements file. Whether an entry is direct, or for development,
    a requirements file does not say (``pip freeze`` lists everything)."""
    parsed = Parsed()
    for number, line in _logical_lines(text):
        words = line.split()
        first = words[0]
        if first in ("-r", "--requirement") or first.startswith("--requirement="):
            target = first.split("=", 1)[1] if "=" in first else " ".join(words[1:2])
            if target:
                parsed.includes.append(target)
            continue
        if first in ("-c", "--constraint") or first.startswith("--constraint="):
            # A constraints file limits versions; it installs nothing.
            continue
        if first in ("-e", "--editable") or first.startswith("--editable="):
            # An editable install is a local checkout or a VCS URL.
            target = first.split("=", 1)[1] if "=" in first else " ".join(words[1:])
            egg = re.search(r"[#&]egg=([A-Za-z0-9._-]+)", target)
            if egg:
                parsed.packages.append(
                    Package(
                        ecosystem=Ecosystem.PYPI,
                        name=pep508.normalize(egg[1]),
                        version=None,
                        how=How.DECLARED,
                        path=path,
                        line=number,
                        spec="",
                        local=True,
                    )
                )
            continue
        option = first.split("=", 1)[0]
        if option in _OPTIONS_WITH_VALUE or option in _FLAGS:
            continue
        if first.startswith("-"):
            parsed.problems.append(Problem(path, number, f"unknown option {first}"))
            continue
        # Per-requirement options (--hash=..., --config-settings ...) follow
        # the requirement itself.
        requirement = re.split(r"\s--?[A-Za-z]", " " + line, maxsplit=1)[0].strip()
        req = pep508.parse(requirement)
        if req is None:
            parsed.problems.append(
                Problem(path, number, f"not a requirement: {requirement[:80]}")
            )
            continue
        parsed.packages.append(_python_package(req, path, number))
    return parsed


def _line_of(text: str, needle: str) -> int | None:
    """The line where a quoted string first appears, for pointing at it."""
    for quote in ('"', "'"):
        at = text.find(quote + needle + quote)
        if at >= 0:
            return text.count("\n", 0, at) + 1
    return None


def _strings(value: object) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def parse_pyproject(text: str, path: str) -> Parsed:
    """pyproject.toml's requirement lists: [project] dependencies and
    optional-dependencies, [dependency-groups] (PEP 735), and the build
    system's requires. Declared, not installed: usually ranges."""
    parsed = Parsed()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        parsed.problems.append(Problem(path, None, f"not valid TOML: {error}"))
        return parsed

    lists: list[tuple[list[str], str, str | None]] = []
    project = data.get("project")
    if isinstance(project, dict):
        lists.append((_strings(project.get("dependencies")), "runtime", None))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group, entries in optional.items():
                lists.append((_strings(entries), "optional", str(group)))
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        # Entries can also be {include-group = "..."}; those name no package.
        for group, entries in groups.items():
            lists.append((_strings(entries), "dev", str(group)))
    build = data.get("build-system")
    if isinstance(build, dict):
        lists.append((_strings(build.get("requires")), "build", None))
    tool = data.get("tool")
    if isinstance(tool, dict) and isinstance(tool.get("poetry"), dict):
        parsed.problems.append(
            Problem(path, None, "Poetry's own dependency tables are not read")
        )

    for entries, scope, group in lists:
        for entry in entries:
            line = _line_of(text, entry)
            req = pep508.parse(entry)
            if req is None:
                parsed.problems.append(
                    Problem(path, line, f"not a requirement: {entry[:80]}")
                )
                continue
            parsed.packages.append(
                _python_package(req, path, line, direct=True, scope=scope, group=group)
            )
    return parsed


def _lock_packages(
    text: str, path: str, is_local: Callable[[dict[str, object]], bool]
) -> Parsed:
    """uv.lock and poetry.lock: TOML with one [[package]] per locked package."""
    parsed = Parsed()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        parsed.problems.append(Problem(path, None, f"not valid TOML: {error}"))
        return parsed
    packages = data.get("package")
    if not isinstance(packages, list):
        parsed.problems.append(Problem(path, None, "no [[package]] entries"))
        return parsed
    # TOML parsers do not report lines: the n-th [[package]] header is the
    # n-th package.
    headers = [
        n
        for n, raw in enumerate(text.splitlines(), start=1)
        if raw.strip() == "[[package]]"
    ]
    for i, entry in enumerate(packages):
        line = headers[i] if i < len(headers) else None
        if not isinstance(entry, dict):
            parsed.problems.append(Problem(path, line, "a package is not a table"))
            continue
        name, version = entry.get("name"), entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            parsed.problems.append(Problem(path, line, "a package without a version"))
            continue
        source = entry.get("source")
        local = isinstance(source, dict) and is_local(source)
        parsed.packages.append(
            Package(
                ecosystem=Ecosystem.PYPI,
                name=pep508.normalize(name),
                version=version,
                how=How.LOCKED,
                path=path,
                line=line,
                local=local,
            )
        )
    return parsed


_UV_LOCAL = {"editable", "virtual", "path", "directory", "git", "url"}
_POETRY_LOCAL = {"directory", "file", "git", "url"}


def parse_uv_lock(text: str, path: str) -> Parsed:
    # source = { registry = "..." } is an index; the other kinds are a local
    # folder, a VCS checkout or a direct URL.
    return _lock_packages(text, path, lambda source: not _UV_LOCAL.isdisjoint(source))


def parse_poetry_lock(text: str, path: str) -> Parsed:
    # [package.source] type = "directory" / "file" / "git" / "url" is not an
    # index; a private index is type "legacy", treated as a registry.
    return _lock_packages(
        text, path, lambda source: source.get("type") in _POETRY_LOCAL
    )


def _site_packages(env: Path) -> list[Path]:
    """An environment's site-packages folders, never through a link."""
    found: list[Path] = []
    for lib in ("lib", "Lib"):
        base = env / lib
        if not base.is_dir() or base.is_symlink():
            continue
        if lib == "Lib":
            candidates = [base / "site-packages"]
        else:
            candidates = [
                Path(e.path) / "site-packages"
                for e in os.scandir(base)
                if e.name.startswith("python") and e.is_dir(follow_symlinks=False)
            ]
        found += [c for c in candidates if c.is_dir() and not c.is_symlink()]
    return sorted(found)


def _metadata_file(entry: os.DirEntry[str]) -> Path:
    if entry.name.endswith(".dist-info"):
        return Path(entry.path) / "METADATA"
    if entry.is_dir():
        return Path(entry.path) / "PKG-INFO"
    return Path(entry.path)  # an .egg-info file is the metadata


def _read_text(path: Path, rel: str, parsed: Parsed) -> str | None:
    """A file's text, or None with a problem recorded: never through a link,
    never a file that is not on this disk (an iCloud placeholder, which
    reading would download)."""
    try:
        st = os.lstat(path)
    except OSError as error:
        parsed.problems.append(Problem(rel, None, f"unreadable: {error}"))
        return None
    if stat.S_ISLNK(st.st_mode):
        parsed.problems.append(Problem(rel, None, "a link, not followed"))
        return None
    if not on_disk(st):
        parsed.problems.append(Problem(rel, None, "not on this disk (iCloud)"))
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        parsed.problems.append(Problem(rel, None, f"unreadable: {error}"))
        return None


def _distributions(
    folder: str, root: Path, parsed: Parsed, scope: str | None
) -> list[tuple[Path, str, str]]:
    """The distributions whose metadata is in ``folder``: their .dist-info
    or .egg-info folder, name and version (added to ``parsed``)."""
    found: list[tuple[Path, str, str]] = []
    headers = HeaderParser()
    for entry in sorted(os.scandir(folder), key=lambda e: e.name):
        if not entry.name.endswith((".dist-info", ".egg-info")):
            continue
        if entry.is_symlink():
            # A link could point anywhere on the machine: never followed.
            rel = Path(entry.path).relative_to(root).as_posix()
            parsed.problems.append(Problem(rel, None, "a link, not followed"))
            continue
        meta = _metadata_file(entry)
        rel = meta.relative_to(root).as_posix()
        text = _read_text(meta, rel, parsed)
        if text is None:
            continue
        message = headers.parsestr(text)
        name, version = message.get("Name"), message.get("Version")
        if not name or not version:
            parsed.problems.append(Problem(rel, None, "no Name or Version"))
            continue
        parsed.packages.append(
            Package(
                ecosystem=Ecosystem.PYPI,
                name=pep508.normalize(name.strip()),
                version=version.strip(),
                how=How.INSTALLED,
                path=rel,
                scope=scope,
                local=scope is None and _installed_locally(Path(entry.path)),
            )
        )
        found.append((Path(entry.path), name.strip(), version.strip()))
    return found


def _sbom(
    path: Path, root: Path, parsed: Parsed, scope: str, itself: str | None
) -> None:
    """The packages a CycloneDX SBOM lists as bundled (sbom.py)."""
    rel = path.relative_to(root).as_posix()
    text = _read_text(path, rel, parsed)
    if text is None:
        return
    try:
        listed, unchecked = sbom.components(text, itself)
    except ValueError as error:
        parsed.problems.append(Problem(rel, None, f"not read: {error}"))
        return
    for ecosystem, name, version in listed:
        parsed.packages.append(
            Package(
                ecosystem=ecosystem,
                name=name,
                version=version,
                how=How.INSTALLED,
                path=rel,
                scope=scope,
            )
        )
    if unchecked:
        parsed.problems.append(
            Problem(
                rel,
                None,
                f"{unchecked} bundled components not checkable "
                "(not PyPI, npm or Go packages)",
            )
        )


def read_environment(root: Path, env: str) -> Parsed:
    """Every distribution installed in the environment at ``root/env``: its
    name and version from the metadata pip (or any installer) wrote. Also
    what distributions bundle inside themselves: other distributions'
    metadata under ``<package>/_vendor`` (setuptools), the SBOM there
    (pip's ``bom.cdx.json``), and SBOMs in ``.dist-info/sboms`` (PEP 770),
    each marked "bundled in <package>"."""
    parsed = Parsed()
    sites = _site_packages(root / env)
    if not sites:
        parsed.problems.append(Problem(env, None, "no site-packages folder found"))
    for site in sites:
        installed = _distributions(str(site), root, parsed, None)
        for dist_info, name, _version in installed:
            sboms = dist_info / "sboms"
            if (
                dist_info.name.endswith(".dist-info")
                and sboms.is_dir()
                and not sboms.is_symlink()
            ):
                for document in sorted(sboms.iterdir()):
                    if document.name.endswith(".json") and not document.is_symlink():
                        _sbom(document, root, parsed, f"bundled in {name}", name)
        for entry in sorted(os.scandir(site), key=lambda e: e.name):
            if not entry.is_dir(follow_symlinks=False):
                continue
            vendor = Path(entry.path) / "_vendor"
            if not vendor.is_dir() or vendor.is_symlink():
                continue
            scope = f"bundled in {entry.name}"
            _distributions(str(vendor), root, parsed, scope)
            bom = vendor / "bom.cdx.json"
            if bom.is_file() and not bom.is_symlink():
                _sbom(bom, root, parsed, scope, entry.name)
    return parsed


def _installed_locally(dist_info: Path) -> bool:
    """Not installed from a package index. Installers write direct_url.json
    (PEP 610) only for a distribution installed from a URL or a folder: an
    editable install of the project itself, a VCS checkout, a wheel's URL."""
    try:
        direct = json.loads((dist_info / "direct_url.json").read_text())
    except OSError, ValueError:
        return False
    return isinstance(direct, dict) and isinstance(direct.get("url"), str)


def python_version(root: Path, env: str) -> str | None:
    """The Python an environment was made with, from its pyvenv.cfg."""
    try:
        text = (root / env / "pyvenv.cfg").read_text(errors="replace")
    except OSError:
        return None
    match = re.search(r"^\s*version(?:_info)?\s*=\s*(\S+)", text, re.MULTILINE)
    return match[1] if match else None
