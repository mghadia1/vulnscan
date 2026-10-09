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
    assert (
        main(["scan", str(repo), "--format", "json", "--no-advisories"]) == EXIT_CLEAN
    )
    report = json.loads(capsys.readouterr().out)
    assert report["tool"] == {"name": "vulnscan", "version": __version__}
    assert report["schema"] == 2
    assert report["summary"] == {
        "files": 4,
        "recognized": 3,
        "environments": 1,
        "symlinks": 0,
        "errors": 0,
        "packages": 0,
        "findings": 0,
        "failing": 0,
        "accepted": 0,
        "undecided": 0,
        "by_severity": {},
    }
    assert report["advisories"] == {"checked": False}
    assert report["files"] == [
        {"path": "Dockerfile", "kind": "dockerfile"},
        {"path": "pyproject.toml", "kind": "pyproject"},
        {"path": "web/package-lock.json", "kind": "npm-lock"},
    ]
    assert report["environments"] == [".venv"]
    assert report["findings"] == []


def test_text_report(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(repo), "--no-advisories"]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "4 files, 3 of them manifests" in out
    assert "Dockerfile: container rules come in Milestone 5" in out
    # The fixture's lockfile is empty: a problem, named, not a crash.
    assert 'web/package-lock.json: no "packages" object' in out
    assert "advisories not checked (--no-advisories)" in out


def test_report_to_a_file(repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    args = ["scan", str(repo), "--format", "json", "--output", str(out)]
    assert main([*args, "--no-advisories"]) == 0
    assert json.loads(out.read_text())["summary"]["recognized"] == 3


def test_the_scan_writes_nothing_into_the_target(repo: Path) -> None:
    def snapshot() -> dict[str, float]:
        return {
            str(p): p.stat().st_mtime for p in sorted(repo.rglob("*")) if p.is_file()
        }

    before = snapshot()
    repo.chmod(0o555)  # and it does not need to
    try:
        assert main(["scan", str(repo), "--format", "json", "--no-advisories"]) == 0
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
        [sys.executable, "-m", "vulnscan", "scan", str(repo), "--format", "json"]
        + ["--no-advisories"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["summary"]["files"] == 4


def osv_zip(path: Path) -> Path:
    import zipfile

    advisory = {
        "id": "PYSEC-1",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2026-0001"],
        "summary": "a test advisory",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Django"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.2.19"}],
                    }
                ],
            }
        ],
    }
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("PYSEC-1.json", json.dumps(advisory))
    return path


def test_update_and_lookup(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = str(tmp_path / "data")
    assert main(["lookup", "PyPI", "django", "1.0", "--data", data]) == EXIT_ERROR
    assert "run `vulnscan update`" in capsys.readouterr().err

    source = osv_zip(tmp_path / "PyPI.zip")
    assert main(["update", "--from", f"PyPI={source}", "--data", data]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "PyPI: 1 advisories (0 withdrawn left out, 0 not readable)" in out
    assert "not checked against the server" in out

    assert main(["lookup", "PyPI", "Django", "3.2.18", "--data", data]) == 1
    out = capsys.readouterr().out
    assert "AFFECTED  PYSEC-1 (CVE-2026-0001): a test advisory" in out
    assert main(["lookup", "PyPI", "django", "3.2.19", "--data", data]) == EXIT_CLEAN
    assert "0 affecting it" in capsys.readouterr().out
    assert main(["lookup", "npm", "ws", "8.0.0", "--data", data]) == EXIT_ERROR
    assert "no npm advisories" in capsys.readouterr().err


def test_update_from_needs_an_ecosystem(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["update", "--from", "x.zip", "--data", str(tmp_path)]) == EXIT_ERROR
    assert "ECOSYSTEM=ZIP" in capsys.readouterr().err
