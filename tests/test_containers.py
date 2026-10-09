"""Each Dockerfile and Compose rule: fires where it should, does not fire
where it should not, and never repeats a value that could be a secret."""

import json
import os
import types
from collections.abc import Callable
from datetime import date, timedelta
from pathlib import Path

import jsonschema
import pytest

from vulnscan.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main
from vulnscan.containers import (
    ConfigFinding,
    check_compose,
    check_dockerfile,
    image,
    scan,
)
from vulnscan.containers.dockerfile import parse
from vulnscan.containers.yamlsub import load
from vulnscan.walk import walk

from helpers import Repo, needs_git

DIGEST = "@sha256:" + "a" * 64
SCHEMA = json.loads(
    (Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text()
)
COMPOSE_DATA = Path(__file__).parent / "data" / "compose"


def dockerfile(text: str) -> list[ConfigFinding]:
    return check_dockerfile("Dockerfile", parse(text), "file")


def rules(text: str) -> list[tuple[str, str, int]]:
    return sorted((f.rule, f.severity, f.line) for f in dockerfile(text))


def compose(text: str) -> list[ConfigFinding]:
    root = load(text)
    assert root is not None
    return check_compose("compose.yaml", root, "file")


def compose_rules(text: str) -> list[tuple[str, str, int]]:
    return sorted((f.rule, f.severity, f.line) for f in compose(text))


SAFE = f"FROM python:3.14-slim{DIGEST}\nUSER 10001\n"


def test_a_safe_dockerfile_has_no_findings() -> None:
    assert rules(SAFE) == []


# -- runs as root ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # No USER: the base image's user, root for most.
        (
            f"FROM python:3.14-slim{DIGEST}\n",
            [("dockerfile/runs-as-root", "medium", 1)],
        ),
        (
            f"FROM python:3.14-slim{DIGEST}\nUSER app\nUSER root\n",
            [("dockerfile/runs-as-root", "medium", 3)],
        ),
        (
            f"FROM python:3.14-slim{DIGEST}\nUSER 0:0\n",
            [("dockerfile/runs-as-root", "medium", 2)],
        ),
        ("FROM scratch\nCOPY app /app\n", [("dockerfile/runs-as-root", "medium", 1)]),
        # Not root: a user, a user from the stage built on, a nonroot base
        # image, a user chosen by a variable (not judged).
        (f"FROM python:3.14-slim{DIGEST}\nUSER app\n", []),
        (f"FROM python:3.14-slim{DIGEST} AS base\nUSER app\nFROM base\nCMD x\n", []),
        (f"FROM gcr.io/distroless/static:nonroot{DIGEST}\nCOPY a /a\n", []),
        (f"FROM cgr.dev/chainguard/python{DIGEST}\n", []),
        (f"FROM python:3.14-slim{DIGEST}\nARG U=app\nUSER $U\n", []),
    ],
)
def test_runs_as_root(text: str, expected: list[tuple[str, str, int]]) -> None:
    assert [r for r in rules(text) if r[0] == "dockerfile/runs-as-root"] == expected


def test_only_the_images_a_file_makes_are_judged() -> None:
    """A build stage that another stage copies from is not an image anyone
    runs; every stage nothing uses is (the last one, and --target ones)."""
    text = (
        f"FROM golang:1.27{DIGEST} AS build\nRUN go build -o /app .\n"
        f"FROM gcr.io/distroless/static:nonroot{DIGEST} AS app\n"
        "COPY --from=build /app /app\n"
        f"FROM debian:13{DIGEST} AS debug\n"
        f"FROM gcr.io/distroless/static:nonroot{DIGEST}\nCOPY --from=app /app /app\n"
    )
    found = [f for f in dockerfile(text) if f.rule == "dockerfile/runs-as-root"]
    assert [f.subject for f in found] == ["stage debug"]


def test_a_mount_from_a_stage_uses_it() -> None:
    text = (
        f"FROM debian:13{DIGEST} AS tools\n"
        f"FROM debian:13{DIGEST}\nRUN --mount=type=bind,from=tools,target=/t ls\n"
        "USER 1000\n"
    )
    assert rules(text) == []


# -- base images -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("FROM node\nUSER 1\n", "dockerfile/base-image-unpinned"),
        ("FROM node:latest\nUSER 1\n", "dockerfile/base-image-unpinned"),
        (
            "FROM registry.local:5000/team/app\nUSER 1\n",
            "dockerfile/base-image-unpinned",
        ),
        ("FROM node:24-alpine\nUSER 1\n", "dockerfile/base-image-no-digest"),
        (
            "ARG V=3.14\nFROM python:${V}-slim\nUSER 1\n",
            "dockerfile/base-image-no-digest",
        ),
        (f"FROM node:24{DIGEST}\nUSER 1\n", None),
        (f"FROM node{DIGEST}\nUSER 1\n", None),
        ("ARG BASE\nFROM $BASE\nUSER 1\n", None),  # chosen at build time
        ("FROM scratch\nUSER 1\n", None),
        (f"FROM a:1{DIGEST} AS a\nFROM a\nUSER 1\n", None),  # a stage
    ],
)
def test_base_images(text: str, expected: str | None) -> None:
    found = [r[0] for r in rules(text) if r[0].startswith("dockerfile/base-image")]
    assert found == ([expected] if expected else [])


def test_an_image_copied_from_is_checked_too() -> None:
    text = SAFE + "COPY --from=nginx:1.27 /etc/nginx /etc/nginx\n"
    assert rules(text) == [("dockerfile/base-image-no-digest", "low", 3)]


def test_image_references() -> None:
    assert image("postgres:16-alpine") == image("postgres:16-alpine")
    ref = image("registry.local:5000/team/app:1.2" + DIGEST)
    assert (ref.name, ref.tag, ref.digest) == (
        "registry.local:5000/team/app",
        "1.2",
        DIGEST[1:],
    )
    assert image("docker.io/library/postgres").short == "postgres"


# -- downloads ----------------------------------------------------------------------


def test_add_from_a_url() -> None:
    text = SAFE + "ADD https://user:pw@example.com/x.tar.gz?token=abc /tmp/\n"
    [f] = dockerfile(text)
    assert (f.rule, f.severity, f.line) == ("dockerfile/add-from-url", "medium", 3)
    # Shown without the user name, password or query.
    assert "https://example.com/x.tar.gz" in f.message
    assert "pw" not in f.message and "abc" not in f.message
    assert rules(SAFE + "ADD --checksum=sha256:00 https://example.com/x /x\n") == []
    assert rules(SAFE + "ADD ./local /x\nCOPY . /app\n") == []


@pytest.mark.parametrize(
    "run",
    [
        "RUN curl -fsSL https://x/install.sh | sh",
        'RUN ["sh", "-c", "curl -fsSL https://x | bash"]',
        "RUN <<EOF\nset -e\nwget -qO- https://x | sh\nEOF",
        "RUN apt-get update \\\n && curl -fsSL https://x \\\n  | bash -",
    ],
)
def test_pipe_to_shell(run: str) -> None:
    assert rules(SAFE + run + "\n") == [("dockerfile/pipe-to-shell", "medium", 3)]


def test_download_then_check_is_fine() -> None:
    text = SAFE + "RUN curl -fsSLo x.sh https://x && sha256sum -c x.sha256 && sh x.sh\n"
    assert rules(text) == []


# -- secrets in ENV and ARG -----------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("ENV DB_PASSWORD=hunter2hunter2", [("dockerfile/secret-in-env", "high", 3)]),
        ("ENV API_KEY $API_KEY", [("dockerfile/secret-in-env", "high", 3)]),
        ('ENV A=1 GITHUB_TOKEN="x y"', [("dockerfile/secret-in-env", "high", 3)]),
        ("ENV TOKEN_PATH=/run/secrets/token", []),
        ("ENV PASSWORD_FILE=/run/secrets/db", []),
        ("ENV DB_PASSWORD=", []),
        ("ARG NPM_TOKEN", [("dockerfile/secret-in-arg", "medium", 3)]),
        ("ARG NPM_TOKEN=abc123", [("dockerfile/secret-in-arg", "high", 3)]),
        ("ARG VERSION=1.0", []),
    ],
)
def test_secrets_in_env_and_arg(
    line: str, expected: list[tuple[str, str, int]]
) -> None:
    found = dockerfile(SAFE + line + "\n")
    assert sorted((f.rule, f.severity, f.line) for f in found) == expected
    for f in found:
        assert "hunter2" not in f.message and "abc123" not in f.message


# -- healthchecks -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "fires"),
    [
        (SAFE + "EXPOSE 8000\n", True),
        (SAFE + "EXPOSE 8000\nHEALTHCHECK CMD curl -f http://localhost:8000/\n", False),
        (SAFE + "EXPOSE 8000\nHEALTHCHECK NONE\n", False),  # decided
        (SAFE, False),  # no port: a tool, not a server
        (f"FROM a:1{DIGEST} AS base\nEXPOSE 80\nFROM base\nUSER 1\n", True),
    ],
)
def test_no_healthcheck(text: str, fires: bool) -> None:
    found = [r for r in rules(text) if r[0] == "dockerfile/no-healthcheck"]
    assert bool(found) == fires
    if fires:
        assert found[0][1] == "low"


# -- Compose ---------------------------------------------------------------------------


def test_privileged_and_capabilities() -> None:
    assert compose_rules("services:\n  a:\n    image: x\n    privileged: true\n") == [
        ("compose/privileged", "high", 4)
    ]
    assert compose_rules("services:\n  a:\n    privileged: false\n") == []
    assert compose_rules(
        "services:\n  a:\n    cap_add: [NET_ADMIN, CAP_SYS_ADMIN]\n"
    ) == [("compose/privileged", "high", 3)]
    assert compose_rules("services:\n  a:\n    cap_add: [NET_BIND_SERVICE]\n") == []


def test_host_namespaces() -> None:
    text = "services:\n  a:\n    network_mode: host\n    pid: host\n"
    assert compose_rules(text) == [
        ("compose/host-namespace", "medium", 3),
        ("compose/host-namespace", "medium", 4),
    ]
    assert compose_rules("services:\n  a:\n    network_mode: bridge\n") == []


@pytest.mark.parametrize(
    ("volume", "fires"),
    [
        ("- /var/run/docker.sock:/var/run/docker.sock", True),
        ("- /var/run/docker.sock:/var/run/docker.sock:ro", True),
        ("- /run/docker.sock:/sock", True),
        (
            "- type: bind\n        source: /var/run/docker.sock\n        target: /s",
            True,
        ),
        ("- ./data:/data", False),
        ("- data:/var/lib/postgresql/data", False),
    ],
)
def test_docker_socket(volume: str, fires: bool) -> None:
    text = f"services:\n  a:\n    volumes:\n      {volume}\n"
    found = compose_rules(text)
    assert found == ([("compose/docker-socket", "high", 4)] if fires else [])


@pytest.mark.parametrize(
    ("image_", "port", "fires"),
    [
        ("postgres:16", "'5432:5432'", True),
        ("postgres:16", "'5432'", True),  # a random host port, everywhere
        ("postgres:16", "'0.0.0.0:5432:5432'", True),
        ("postgres:16", "'${PORT:-5432}:5432'", True),
        ("postgres:16", "'127.0.0.1:5433:5432'", False),
        ("postgres:16", "'[::1]:5432:5432'", False),
        ("docker.io/library/redis:8", "'6379:6379'", True),
        ("pgvector/pgvector:0.8.6-pg17", "'5432:5432'", True),
        ("nginx:1.27", "'80:80'", False),  # not a database
        ("postgres:16", "{target: 5432, published: 5432}", True),
        ("postgres:16", "{target: 5432, published: 5432, host_ip: 127.0.0.1}", False),
    ],
)
def test_databases_published_everywhere(image_: str, port: str, fires: bool) -> None:
    text = f"services:\n  db:\n    image: {image_}\n    ports:\n      - {port}\n"
    found = compose_rules(text)
    assert found == (
        [("compose/database-port-published", "medium", 5)] if fires else []
    )


def test_a_database_with_no_ports_is_fine() -> None:
    assert compose_rules("services:\n  db:\n    image: postgres:16\n") == []


@pytest.mark.parametrize(
    ("environment", "expected"),
    [
        (
            "POSTGRES_USER: shop9\n      POSTGRES_PASSWORD: shop9",
            [("compose/default-password", "medium", 5)],
        ),
        ("POSTGRES_PASSWORD: postgres", [("compose/default-password", "medium", 4)]),
        (
            "POSTGRES_PASSWORD: ${PG_PASS:-changeme}",
            [("compose/default-password", "medium", 4)],
        ),
        (
            "DB_URL: postgresql://shop9:shop9@db:5432/shop9",
            [("compose/default-password", "medium", 4)],
        ),
        ("POSTGRES_HOST_AUTH_METHOD: trust", [("compose/default-password", "high", 4)]),
        (
            "MYSQL_ALLOW_EMPTY_PASSWORD: 'yes'",
            [("compose/default-password", "high", 4)],
        ),
        ("POSTGRES_PASSWORD: ${PG_PASS}", []),
        ("POSTGRES_PASSWORD: 'v8#Kq2!xR4m@Lz'", []),
        ("POSTGRES_PASSWORD_FILE: /run/secrets/db", []),
        ("DB_URL: postgresql://shop9:${PG_PASS}@db/shop9", []),
        ("POSTGRES_PASSWORD:", []),  # passed through from the shell
    ],
)
def test_default_passwords(
    environment: str, expected: list[tuple[str, str, int]]
) -> None:
    text = f"services:\n  db:\n    environment:\n      {environment}\n"
    found = compose(text)
    assert sorted((f.rule, f.severity, f.line) for f in found) == expected
    for f in found:
        assert "shop9" not in f.message and "changeme" not in f.message


def test_list_form_environment() -> None:
    text = "services:\n  db:\n    environment:\n      - POSTGRES_PASSWORD=password\n"
    assert compose_rules(text) == [("compose/default-password", "medium", 4)]


def test_one_password_shared_by_services_is_one_finding() -> None:
    text = (
        "x-db: &db postgresql://app7:app7@db/app7\n"
        "services:\n"
        "  api:\n    environment:\n      DATABASE_URL: *db\n"
        "  worker:\n    environment:\n      DATABASE_URL: *db\n"
    )
    [f] = compose(text)
    assert f.line == 1
    assert "services api and worker" in f.message


def test_the_real_compose_files() -> None:
    """My own files: SurgiServe keeps its database on localhost but uses
    its own name as the password; Gatekeeper's Redis is on localhost;
    SyncBoard's Redis is not published."""
    found = {
        name: sorted(
            (f.rule, f.line) for f in compose((COMPOSE_DATA / name).read_text())
        )
        for name in (
            "surgiserve.compose.yaml",
            "gatekeeper.compose.yaml",
            "syncboard.compose.replicas.yaml",
        )
    }
    assert found == {
        "surgiserve.compose.yaml": [
            ("compose/default-password", 4),
            ("compose/default-password", 12),
        ],
        "gatekeeper.compose.yaml": [],
        "syncboard.compose.replicas.yaml": [],
    }


# -- files, git, the CLI -------------------------------------------------------------


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "Dockerfile").write_text(
        "FROM python:3.14-slim\nENV DB_PASSWORD=s3cretvalue\nEXPOSE 8000\n"
    )
    (root / "compose.yaml").write_text(
        "services:\n  db:\n    image: postgres:16\n    ports: ['5432:5432']\n"
        "    environment:\n      POSTGRES_USER: app7\n      POSTGRES_PASSWORD: app7\n"
        "  tools:\n    image: docker:27\n    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n"
    )
    return root


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = main(args)
    out = capsys.readouterr()
    return code, out.out + out.err


def test_the_cli(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, text = _run(["scan", str(project), "--no-advisories", "--no-secrets"], capsys)
    assert code == EXIT_FINDINGS
    assert "containers: 1 Dockerfiles and 1 Compose files read" in text
    assert "7 container findings, 7 failing" in text
    for value in ("s3cretvalue", "app7"):
        assert value not in text
    code, out = _run(
        ["scan", str(project), "--no-advisories", "--no-secrets", "--format", "json"],
        capsys,
    )
    report = json.loads(out)
    assert sorted(f["rule"] for f in report["containers"]["findings"]) == [
        "compose/database-port-published",
        "compose/default-password",
        "compose/docker-socket",
        "dockerfile/base-image-no-digest",
        "dockerfile/no-healthcheck",
        "dockerfile/runs-as-root",
        "dockerfile/secret-in-env",
    ]
    code, out = _run(
        ["scan", str(project), "--no-advisories", "--no-secrets", "--format", "sarif"],
        capsys,
    )
    sarif = json.loads(out)
    jsonschema.validate(sarif, SCHEMA)
    assert {r["ruleId"] for r in sarif["runs"][0]["results"]} >= {
        "compose/docker-socket",
        "dockerfile/secret-in-env",
    }
    assert "s3cretvalue" not in out and "app7" not in out
    code, out = _run(
        ["scan", str(project), "--no-advisories", "--no-secrets", "--no-containers"],
        capsys,
    )
    assert code == EXIT_CLEAN
    assert "not checked (--no-containers)" in out


def _baseline(target: Path, entries: list[dict[str, str]]) -> None:
    lines = []
    for entry in entries:
        lines.append("[[accept]]")
        for key, value in entry.items():
            lines.append(
                f"{key} = {value}" if key == "expires" else f'{key} = "{value}"'
            )
    (target / ".vulnscan.toml").write_text("\n".join(lines) + "\n")


def test_accepting_rules(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    later = (date.today() + timedelta(days=30)).isoformat()
    earlier = (date.today() - timedelta(days=1)).isoformat()
    args = ["scan", str(project), "--no-advisories", "--no-secrets"]
    everything = sorted(
        {f.rule for f in scan(project.resolve(), walk(project.resolve())).findings}
    )
    _baseline(
        project,
        [{"rule": r, "reason": "a test", "expires": later} for r in everything]
        + [
            {
                "rule": "compose/privileged",
                "path": "x.yaml",
                "reason": "x",
                "expires": later,
            }
        ],
    )
    code, text = _run(args, capsys)
    assert code == EXIT_CLEAN
    assert "7 accepted (not failing):" in text
    assert "acceptance of compose/privileged in x.yaml matches no finding" in text
    # Only in another file: does not hold.
    _baseline(
        project,
        [
            {
                "rule": "compose/docker-socket",
                "path": "other.yaml",
                "reason": "x",
                "expires": later,
            }
        ],
    )
    code, out = _run([*args, "--format", "json"], capsys)
    socket = [
        f
        for f in json.loads(out)["containers"]["findings"]
        if f["rule"] == "compose/docker-socket"
    ]
    assert [f["accepted"] for f in socket] == [None]
    assert code == EXIT_FINDINGS
    _baseline(
        project,
        [{"rule": "compose/docker-socket", "reason": "x", "expires": earlier}],
    )
    code, text = _run(args, capsys)
    assert "acceptance of compose/docker-socket expired" in text
    _baseline(project, [{"rule": "compose/nonsense", "reason": "x", "expires": later}])
    code, text = _run(args, capsys)
    assert code == EXIT_ERROR and "no such rule" in text


@needs_git
def test_a_file_not_on_this_disk_is_read_from_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = Repo(tmp_path / "r")
    repo.write("Dockerfile", "FROM node\n")
    repo.commit()
    repo.write("api/Dockerfile", "FROM node\n")  # not committed
    root = str(repo.path.resolve())
    offline = {"Dockerfile", "api/Dockerfile"}
    real_lstat: Callable[..., os.stat_result] = os.lstat

    def lstat(path: str | Path) -> object:
        st = real_lstat(path)
        if os.path.relpath(str(path), root) in offline:
            return types.SimpleNamespace(
                st_mode=st.st_mode, st_size=st.st_size, st_flags=0x40000000
            )
        return st

    monkeypatch.setattr(os, "lstat", lstat)
    result = scan(repo.path.resolve(), walk(repo.path.resolve()))
    files = {f.path: (f.source, f.error) for f in result.files}
    assert files["Dockerfile"] == ("HEAD", None)
    assert files["api/Dockerfile"] == (
        None,
        "not on this disk (iCloud), and not committed",
    )
    assert {f.source for f in result.findings} == {"HEAD"}
    # HEAD's branch not on disk: HEAD comes from its reflog.
    offline.add(".git/refs/heads/main")
    result = scan(repo.path.resolve(), walk(repo.path.resolve()))
    assert {f.path: f.source for f in result.files}["Dockerfile"] == "HEAD"
    # And when its reflog is not either:
    offline.add(".git/logs/HEAD")
    result = scan(repo.path.resolve(), walk(repo.path.resolve()))
    files = {f.path: (f.source, f.error) for f in result.files}
    assert files["Dockerfile"] == (
        None,
        "not on this disk (iCloud), and neither is its HEAD",
    )


def test_unreadable_files_are_named(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("RUN <<EOF\nnever ends\n")
    (tmp_path / "compose.yaml").write_text("services: !reset {}\n")
    result = scan(tmp_path.resolve(), walk(tmp_path.resolve()))
    errors = {f.path: f.error for f in result.files}
    assert "heredoc EOF never ends" in (errors["Dockerfile"] or "")
    assert "tags are not read" in (errors["compose.yaml"] or "")
    assert result.findings == ()
