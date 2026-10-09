import pytest

from vulnscan.classify import Kind, classify


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("requirements.txt", Kind.REQUIREMENTS),
        ("requirements-dev.txt", Kind.REQUIREMENTS),
        ("requirements/base.txt", Kind.REQUIREMENTS),
        ("api/pyproject.toml", Kind.PYPROJECT),
        ("uv.lock", Kind.UV_LOCK),
        ("poetry.lock", Kind.POETRY_LOCK),
        ("Pipfile.lock", Kind.PIPFILE_LOCK),
        ("web/package-lock.json", Kind.NPM_LOCK),
        ("npm-shrinkwrap.json", Kind.NPM_LOCK),
        ("package.json", Kind.NPM_MANIFEST),
        ("yarn.lock", Kind.YARN_LOCK),
        ("pnpm-lock.yaml", Kind.PNPM_LOCK),
        ("go.mod", Kind.GO_MOD),
        ("go.sum", Kind.GO_SUM),
        ("api/pom.xml", Kind.MAVEN_POM),
        ("build.gradle.kts", Kind.GRADLE),
        ("renv.lock", Kind.RENV_LOCK),
        ("Cargo.lock", Kind.CARGO_LOCK),
        ("Dockerfile", Kind.DOCKERFILE),
        ("Dockerfile.worker", Kind.DOCKERFILE),
        ("bench/api.Dockerfile", Kind.DOCKERFILE),
        ("Containerfile", Kind.DOCKERFILE),
        ("compose.yaml", Kind.COMPOSE),
        ("docker-compose.yml", Kind.COMPOSE),
        ("compose.override.yaml", Kind.COMPOSE),
        ("bench/compose.bench.yaml", Kind.COMPOSE),
    ],
)
def test_recognised(path: str, kind: Kind) -> None:
    assert classify(path) is kind


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "notes.txt",
        "requirements.txt.bak",
        "docs/requirements.md",
        "dockerfile-notes.md",
        "composer.json",  # PHP, not Compose
        "decompose.yaml",
        "compose.json",
        "src/go.mod.go",
    ],
)
def test_not_recognised(path: str) -> None:
    assert classify(path) is None
