"""Version ordering, by ecosystem, written by hand (no packaging, no semver
library: those are used only in the tests, to check these against).

``order(ecosystem, name, range_type)`` returns the function that turns a
version string into a sort key for that ecosystem, or None for a string
that is not a version there. Keys of one ecosystem compare with each other
only.
"""

from collections.abc import Callable

from vulnscan.versions import pep440, semver

Key = tuple[object, ...]
Order = Callable[[str], Key | None]


def _pep440(text: str) -> Key | None:
    version = pep440.parse(text)
    return None if version is None else pep440.key(version)


def _semver(text: str) -> Key | None:
    version = semver.parse(text)
    return None if version is None else semver.key(version)


def _go_module(text: str) -> Key | None:
    version = semver.from_go(text)
    return None if version is None else semver.key(version)


def _go_toolchain(text: str) -> Key | None:
    version = semver.from_go_toolchain(text)
    return None if version is None else semver.key(version)


# The Go standard library and the go command are released as Go itself is.
GO_TOOLCHAIN_NAMES = frozenset({"stdlib", "toolchain"})


def order(ecosystem: str, name: str, range_type: str = "ECOSYSTEM") -> Order | None:
    """How versions of ``name`` in ``ecosystem`` sort; None if not known here."""
    if range_type == "SEMVER":
        # OSV's SEMVER ranges are SemVer whatever the ecosystem.
        if ecosystem == "Go":
            return _go_toolchain if name in GO_TOOLCHAIN_NAMES else _go_module
        return _semver
    if range_type != "ECOSYSTEM":
        return None  # GIT ranges need the repository
    if ecosystem == "PyPI":
        return _pep440
    if ecosystem == "npm":
        return _semver
    if ecosystem == "Go":
        return _go_toolchain if name in GO_TOOLCHAIN_NAMES else _go_module
    return None
