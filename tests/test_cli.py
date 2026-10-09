import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vulnscan import __version__
from vulnscan.cli import EXIT_CLEAN, EXIT_ERROR, main

SRC = Path(__file__).resolve().parents[1] / "src"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "web").mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "web/package-lock.json").write_text("{}")
    (root / "Dockerfile").write_text("FROM python:3.14-slim\n")
    (root / "README.md").write_text("# x\n")
    (root / ".venv").mkdir()
    (root / ".venv/pyvenv.cfg").write_text("home = /usr/bin\n")
    return root


def test_json_report(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(repo), "--format", "json"]) == EXIT_CLEAN
    report = json.loads(capsys.readouterr().out)
    assert report["tool"] == {"name": "vulnscan", "version": __version__}
    assert report["schema"] == 1
    assert report["summary"] == {
        "files": 4,
        "recognized": 3,
        "environments": 1,
        "symlinks": 0,
        "errors": 0,
        "findings": 0,
    }
    assert report["files"] == [
        {"path": "Dockerfile", "kind": "dockerfile"},
        {"path": "pyproject.toml", "kind": "pyproject"},
        {"path": "web/package-lock.json", "kind": "npm-lock"},
    ]
    assert report["environments"] == [".venv"]
    assert report["findings"] == []


def test_text_report(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(repo)]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "4 files, 3 of them manifests" in out
    assert "Dockerfile: container rules come in Milestone 5" in out
    # The fixture's lockfile is empty: a problem, named, not a crash.
    assert 'web/package-lock.json: no "packages" object' in out
    assert "no findings" in out


def test_report_to_a_file(repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    assert main(["scan", str(repo), "--format", "json", "--output", str(out)]) == 0
    assert json.loads(out.read_text())["summary"]["recognized"] == 3


def test_the_scan_writes_nothing_into_the_target(repo: Path) -> None:
    def snapshot() -> dict[str, float]:
        return {
            str(p): p.stat().st_mtime for p in sorted(repo.rglob("*")) if p.is_file()
        }

    before = snapshot()
    repo.chmod(0o555)  # and it does not need to
    try:
        assert main(["scan", str(repo), "--format", "json"]) == EXIT_CLEAN
    finally:
        repo.chmod(0o755)
    assert snapshot() == before


@pytest.mark.parametrize("what", ["missing", "file"])
def test_a_target_that_is_not_a_directory_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], what: str
) -> None:
    target = tmp_path / "x"
    if what == "file":
        target.write_text("")
    assert main(["scan", str(target)]) == EXIT_ERROR
    assert "vulnscan:" in capsys.readouterr().err


def test_bad_options_exit_2() -> None:
    with pytest.raises(SystemExit) as exit_:
        main(["scan", ".", "--format", "xml"])
    assert exit_.value.code == EXIT_ERROR


def test_runs_as_a_module(repo: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "vulnscan", "scan", str(repo), "--format", "json"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["summary"]["files"] == 4
