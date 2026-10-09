"""Python requirement strings (PEP 508), as far as an inventory needs them.

``fastapi[standard]>=0.115,<1 ; python_version >= "3.12"`` is a name, extras,
version specifiers, and a marker. The inventory needs the name (normalised,
PEP 503), and whether the specifiers pin one exact version. Markers are kept
as text and not evaluated: a requirement for another platform is still
reported, marked with its marker.
"""

import re
from dataclasses import dataclass

_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
# A version is the characters PEP 440 uses (an "=" left over from a broken
# operator is not one: "foo>=" was once read as "> =").
_SPEC = re.compile(r"\s*(===|~=|==|!=|<=|>=|<|>)\s*([A-Za-z0-9][A-Za-z0-9.*+!_-]*)\s*")
_REQUIREMENT = re.compile(
    rf"""^\s*
    (?P<name>{_NAME})
    \s*(?:\[(?P<extras>[^\]]*)\])?
    \s*(?:
        @\s*(?P<url>\S+)
      | (?P<specs>\(?[^;]*?\)?)
    )
    \s*(?:;\s*(?P<marker>.*?))?\s*$""",
    re.VERBOSE,
)


def normalize(name: str) -> str:
    """PEP 503: case and runs of "-", "_" and "." do not matter."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Requirement:
    name: str  # as written
    extras: tuple[str, ...]
    specifiers: tuple[tuple[str, str], ...]  # (operator, version)
    url: str | None
    marker: str | None

    @property
    def normalized(self) -> str:
        return normalize(self.name)

    @property
    def pinned(self) -> str | None:
        """The one exact version these specifiers allow, if they allow one."""
        if self.url is None and len(self.specifiers) == 1:
            op, version = self.specifiers[0]
            if op in ("==", "===") and "*" not in version:
                return version
        return None

    @property
    def spec(self) -> str:
        """The specifiers as one string: ">=1.0,<2"; "" for any version."""
        return ",".join(op + version for op, version in self.specifiers)


def parse(text: str) -> Requirement | None:
    """A requirement string, or None if it is not one."""
    match = _REQUIREMENT.match(text)
    if match is None:
        return None
    extras: tuple[str, ...] = ()
    if match["extras"] is not None:
        extras = tuple(e.strip() for e in match["extras"].split(",") if e.strip())
        if not all(re.fullmatch(_NAME, e) for e in extras):
            return None
    specifiers: list[tuple[str, str]] = []
    specs = (match["specs"] or "").strip()
    if specs.startswith("(") and specs.endswith(")"):
        specs = specs[1:-1]
    if specs:
        for part in specs.split(","):
            spec = _SPEC.fullmatch(part)
            if spec is None:
                return None
            specifiers.append((spec[1], spec[2]))
    marker = match["marker"] or None
    return Requirement(
        name=match["name"],
        extras=extras,
        specifiers=tuple(specifiers),
        url=match["url"],
        marker=marker,
    )
