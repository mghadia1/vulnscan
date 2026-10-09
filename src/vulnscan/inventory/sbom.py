"""Packages bundled inside other packages, from the SBOMs that list them.

Some distributions carry copies of other packages inside themselves: pip
bundles urllib3, requests, certifi and others under ``pip/_vendor``, and
lists them in a CycloneDX SBOM there (``bom.cdx.json``); PEP 770 puts a
distribution's own SBOMs in ``<name>.dist-info/sboms/``. That code runs
whenever its bundler does, so its vulnerabilities count.

A CycloneDX JSON document's components (nested ones too) are read by their
package URL (purl, ``pkg:pypi/urllib3@2.7.0``): PyPI, npm and Go ones
become packages; a component that is part of the distribution itself
(``pkg:pypi/pillow@12.3.0#c-ext/...`` in Pillow's own SBOM) is not another
package; any other kind (C libraries as ``pkg:generic/...``) is counted as
not checkable, since OSV's PyPI, npm and Go data cannot say anything about
it.
"""

import json
from collections.abc import Iterator
from urllib.parse import unquote

from vulnscan.inventory import pep508
from vulnscan.inventory.model import Ecosystem

_TYPES = {"pypi": Ecosystem.PYPI, "npm": Ecosystem.NPM, "golang": Ecosystem.GO}


def purl(text: str) -> tuple[str, str, str | None, str | None] | None:
    """A package URL's type, name (with its namespace), version and
    subpath: ``pkg:npm/%40scope/name@1.0#lib`` is ("npm", "@scope/name",
    "1.0", "lib")."""
    if not text.startswith("pkg:"):
        return None
    rest = text[4:].lstrip("/")
    rest, _, subpath = rest.partition("#")
    rest, _, _qualifiers = rest.partition("?")
    type_, sep, path = rest.partition("/")
    if not sep or not type_:
        return None
    # The version follows the last "@", unless that "@" begins a scope
    # ("@scope/name") or is followed by more path.
    at = path.rfind("@")
    if at > 0 and "/" not in path[at + 1 :]:
        path, version = path[:at], path[at + 1 :]
    else:
        version = ""
    parts = [unquote(p) for p in path.split("/") if p]
    if not parts:
        return None
    return (
        type_.lower(),
        "/".join(parts),
        unquote(version) or None,
        unquote(subpath) or None,
    )


def _components(node: object) -> Iterator[dict[str, object]]:
    if isinstance(node, dict):
        for component in node.get("components", []) or []:
            if isinstance(component, dict):
                yield component
                yield from _components(component)


def components(
    text: str, itself: str | None = None
) -> tuple[list[tuple[Ecosystem, str, str]], int]:
    """The (ecosystem, name, version) of each bundled package an SBOM lists,
    and how many components could not be checked. ``itself`` is the
    distribution the SBOM belongs to (its parts are not other packages).
    Raises ValueError for a document that is not CycloneDX JSON."""
    data = json.loads(text)
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX document")
    found: list[tuple[Ecosystem, str, str]] = []
    unchecked = 0
    seen: set[tuple[Ecosystem, str, str]] = set()
    for component in _components(data):
        ref = component.get("purl")
        parsed = purl(ref) if isinstance(ref, str) else None
        if parsed is None:
            if component.get("version"):
                unchecked += 1  # named, versioned, but not a package URL
            continue
        type_, name, version, subpath = parsed
        ecosystem = _TYPES.get(type_)
        if ecosystem is None or version is None:
            unchecked += 1
            continue
        if ecosystem is Ecosystem.PYPI:
            name = pep508.normalize(name)
            if itself is not None and name == pep508.normalize(itself):
                continue  # a part of the distribution itself
        elif subpath is not None and itself is not None and name == itself:
            continue
        item = (ecosystem, name, version)
        if item not in seen:
            seen.add(item)
            found.append(item)
    return found, unchecked
