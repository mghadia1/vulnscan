import os
from pathlib import Path

import pytest

import vulnscan.inventory as inventory
from vulnscan.inventory import build
from vulnscan.walk import walk


def write(root: Path, path: str, text: str = "") -> None:
    file = root / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text)


def test_includes_are_followed_inside_the_target_only(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write(
        root, "requirements.txt", "-r reqs/base.txt\n-r ../outside.txt\nflask==3.0.0\n"
    )
    write(root, "reqs/base.txt", "-r ../requirements.txt\nrequests==2.32.3\n")
    write(tmp_path, "outside.txt", "evil==6.6.6\n")
    os.symlink(tmp_path / "outside.txt", root / "via-link.txt")
    write(root, "requirements-dev.txt", "-r via-link.txt\n")

    inv = build(walk(root))
    names = {(p.name, p.path) for p in inv.packages}
    # base.txt is not named like a requirements file: read because included.
    # The include cycle back to requirements.txt ends.
    assert names == {("flask", "requirements.txt"), ("requests", "reqs/base.txt")}
    assert sorted(p.message for p in inv.problems) == [
        "includes ../outside.txt, not found in the target",
        "includes via-link.txt, not found in the target",
    ]


def test_files_not_read_say_why(tmp_path: Path) -> None:
    for path in ["go.sum", "renv.lock", "api/pom.xml", "Dockerfile", "yarn.lock"]:
        write(tmp_path, path)
    write(tmp_path, "web/package-lock.json", '{"lockfileVersion": 3, "packages": {}}')
    write(tmp_path, "web/client/package.json", '{"dependencies": {"ws": "^8"}}')
    write(tmp_path, "solo/package.json", '{"dependencies": {"ws": "^8"}}')
    inv = build(walk(tmp_path))
    assert dict(inv.not_read) == {
        "Dockerfile": "container rules come in Milestone 5",
        "api/pom.xml": "Java (Maven) dependencies are not covered",
        "go.sum": "go.mod lists every module the build needs",
        "renv.lock": "R (CRAN) dependencies are not covered",
        "web/client/package.json": "covered by web/package-lock.json",
        "yarn.lock": "yarn.lock is not read yet",
    }
    # A package.json with no lockfile above it is read, as declared ranges.
    assert [(p.name, p.spec, p.path) for p in inv.packages] == [
        ("ws", "^8", "solo/package.json")
    ]


def test_unreadable_files_are_problems(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "go.mod").write_bytes(b"module x\n\xff\xfe\n")
    write(tmp_path, "requirements.txt", "x==1.0\n" * 100)
    monkeypatch.setattr(inventory, "MAX_BYTES", 50)
    inv = build(walk(tmp_path))
    assert inv.packages == ()
    assert sorted(p.message for p in inv.problems) == [
        "larger than 50 MB; not read",
        "not UTF-8; not read",
    ]


def test_environments_are_read(tmp_path: Path) -> None:
    write(tmp_path, "pyproject.toml", '[project]\ndependencies = ["fastapi>=0.142"]\n')
    write(tmp_path, ".venv/pyvenv.cfg", "version = 3.14.7\n")
    write(
        tmp_path,
        ".venv/lib/python3.14/site-packages/fastapi-0.142.0.dist-info/METADATA",
        "Name: fastapi\nVersion: 0.142.0\n",
    )
    inv = build(walk(tmp_path))
    assert [(p.name, p.version, p.how.value) for p in inv.packages] == [
        ("fastapi", "0.142.0", "installed"),
        ("fastapi", None, "declared"),
    ]
    [env] = inv.environments
    assert (env.path, env.python, env.packages) == (".venv", "3.14.7", 1)
