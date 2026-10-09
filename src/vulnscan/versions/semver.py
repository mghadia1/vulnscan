"""Semantic versions (SemVer 2.0.0): what npm and Go modules use, and what
OSV's SEMVER ranges are written in.

``MAJOR.MINOR.PATCH[-pre.release][+build]``. Precedence (the spec's section
11): the three numbers, then a version with a pre-release before the same
version without one; pre-release identifiers compared one by one, numbers
numerically and below words, words in ASCII order, and a shorter list
before a longer one it is a prefix of. Build metadata does not count.
Strict: what the spec's own regular expression accepts, nothing looser.
"""

import re
from dataclasses import dataclass

# The regular expression semver.org gives, with names.
_PATTERN = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<build>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    pre: tuple[str | int, ...]  # () for a release
    build: str | None


def parse(text: str) -> Version | None:
    m = _PATTERN.match(text)
    if m is None:
        return None
    pre: tuple[str | int, ...] = ()
    if m["pre"] is not None:
        pre = tuple(int(i) if i.isdigit() else i for i in m["pre"].split("."))
    return Version(int(m["major"]), int(m["minor"]), int(m["patch"]), pre, m["build"])


def key(version: Version) -> tuple[object, ...]:
    if not version.pre:
        pre: tuple[object, ...] = (1,)  # a release, after all its pre-releases
    else:
        pre = (
            0,
            tuple((0, i, "") if isinstance(i, int) else (1, 0, i) for i in version.pre),
        )
    return (version.major, version.minor, version.patch, pre)


def from_go(text: str) -> Version | None:
    """A Go module version ("v1.2.3", "v2.0.0+incompatible", a pseudo-version)
    is SemVer with a "v" in front: OSV writes it without the "v"."""
    return parse(text[1:] if text.startswith("v") else text)


_GO_RELEASE = re.compile(r"^(?:go)?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:(beta|rc)(\d+))?$")


def from_go_toolchain(text: str) -> Version | None:
    """A Go release ("go1.21rc2", "1.21", "1.21.3") as SemVer, the way the Go
    vulnerability database writes the standard library's versions:
    1.21rc2 is 1.21.0-rc.2, and 1.21 is 1.21.0."""
    m = _GO_RELEASE.match(text)
    if m is None:
        return parse(text)
    major, minor, patch, pre_kind, pre_n = m.groups()
    pre: tuple[str | int, ...] = (pre_kind, int(pre_n)) if pre_kind else ()
    return Version(int(major), int(minor or 0), int(patch or 0), pre, None)
