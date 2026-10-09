"""What an inventory is made of: packages, and the problems met reading them."""

from dataclasses import dataclass, field
from enum import StrEnum


class Ecosystem(StrEnum):
    """Spelled as OSV spells them, so advisories can be looked up by it."""

    PYPI = "PyPI"
    NPM = "npm"
    GO = "Go"


class How(StrEnum):
    """How sure the inventory is of a version, most sure first."""

    INSTALLED = "installed"  # in an environment on disk: what actually runs here
    LOCKED = "locked"  # a lockfile's resolved version: what an install gets
    PINNED = "pinned"  # a manifest allowing exactly one version
    DECLARED = "declared"  # a manifest's range: which version is used is not known


@dataclass(frozen=True)
class Package:
    ecosystem: Ecosystem
    name: str  # normalised for its ecosystem
    version: str | None  # exact; None for a declared range
    how: How
    path: str  # the file it was found in, relative to the target
    line: int | None = None
    spec: str | None = None  # a declared range ("" for any version)
    # A direct dependency of the project; None when the source cannot say.
    direct: bool | None = None
    # "runtime", "dev", "optional", "build", or None when the source cannot say.
    scope: str | None = None
    group: str | None = None  # an extra or dependency group's name
    marker: str | None = None  # a Python environment marker, not evaluated
    # Not a release from the public registry (an editable install, a
    # workspace, a path, a git checkout): never matched against advisories.
    local: bool = False


@dataclass(frozen=True)
class Problem:
    path: str
    line: int | None
    message: str


@dataclass
class Parsed:
    """What one parser found in one file."""

    packages: list[Package] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    # Other files this one includes (a requirements file's -r), relative to it.
    includes: list[str] = field(default_factory=list)
