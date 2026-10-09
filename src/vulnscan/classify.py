"""What kind of file a path is, as far as a scan is concerned.

Only files a scan has a reason to read get a kind: dependency manifests and
lockfiles, Dockerfiles, and Compose files. Recognised by name, as the tools
that use them do; nothing is opened here.
"""

from enum import StrEnum
from pathlib import PurePosixPath


class Kind(StrEnum):
    REQUIREMENTS = "requirements"  # requirements*.txt, requirements/*.txt
    PYPROJECT = "pyproject"  # pyproject.toml
    UV_LOCK = "uv-lock"
    POETRY_LOCK = "poetry-lock"
    PIPFILE_LOCK = "pipfile-lock"
    NPM_LOCK = "npm-lock"  # package-lock.json, npm-shrinkwrap.json
    NPM_MANIFEST = "npm-manifest"  # package.json
    YARN_LOCK = "yarn-lock"
    PNPM_LOCK = "pnpm-lock"
    GO_MOD = "go-mod"
    GO_SUM = "go-sum"
    MAVEN_POM = "maven-pom"
    GRADLE = "gradle"
    RENV_LOCK = "renv-lock"
    CARGO_LOCK = "cargo-lock"
    DOCKERFILE = "dockerfile"
    COMPOSE = "compose"


_EXACT = {
    "pyproject.toml": Kind.PYPROJECT,
    "uv.lock": Kind.UV_LOCK,
    "poetry.lock": Kind.POETRY_LOCK,
    "Pipfile.lock": Kind.PIPFILE_LOCK,
    "package-lock.json": Kind.NPM_LOCK,
    "npm-shrinkwrap.json": Kind.NPM_LOCK,
    "package.json": Kind.NPM_MANIFEST,
    "yarn.lock": Kind.YARN_LOCK,
    "pnpm-lock.yaml": Kind.PNPM_LOCK,
    "go.mod": Kind.GO_MOD,
    "go.sum": Kind.GO_SUM,
    "pom.xml": Kind.MAVEN_POM,
    "build.gradle": Kind.GRADLE,
    "build.gradle.kts": Kind.GRADLE,
    "renv.lock": Kind.RENV_LOCK,
    "Cargo.lock": Kind.CARGO_LOCK,
    "Dockerfile": Kind.DOCKERFILE,
    "Containerfile": Kind.DOCKERFILE,
}

_COMPOSE_STEMS = ("compose", "docker-compose")


def classify(path: str) -> Kind | None:
    """The kind of the file at ``path`` (relative, with "/"), or None."""
    p = PurePosixPath(path)
    name = p.name
    if name in _EXACT:
        return _EXACT[name]
    if name.endswith(".txt") and (
        name.startswith("requirements") or p.parent.name == "requirements"
    ):
        return Kind.REQUIREMENTS
    # Dockerfile.dev, api.Dockerfile
    if name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return Kind.DOCKERFILE
    # compose.yaml, docker-compose.yml, compose.override.yaml, compose.bench.yml
    if p.suffix in (".yaml", ".yml") and any(
        name == stem + p.suffix or name.startswith(stem + ".")
        for stem in _COMPOSE_STEMS
    ):
        return Kind.COMPOSE
    return None
