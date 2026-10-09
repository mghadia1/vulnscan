"""The secret scan end to end: fake secrets planted in a real repository's
files and history (made with git), found with where they are and what to
do; decoys not found; and no secret anywhere in any output."""

import json
import os
import random
import types
from collections.abc import Callable
from datetime import date, timedelta
from pathlib import Path

import jsonschema
import pytest

from vulnscan import secrets
from vulnscan.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main
from vulnscan.secrets import SecretScan
from vulnscan.walk import walk

from helpers import FAKES, FIXED, Repo, jwt, leaks, needs_git, pem, private_key_body

pytestmark = needs_git

SCHEMA = json.loads(
    (Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text()
)


class Planted:
    """The fake secrets of one scenario, by name, with each one's fixed
    (showable) prefix length."""

    def __init__(self) -> None:
        self.values: dict[str, tuple[str, int]] = {}
        self.rng = random.Random(2026)

    def token(self, name: str, rule: str) -> str:
        value = FAKES[rule](self.rng)
        self.values[name] = (value, FIXED[rule])
        return value

    def other(self, name: str, value: str) -> str:
        self.values[name] = (value, 0)
        return value

    def assert_not_in(self, output: str) -> None:
        for name, (value, fixed) in self.values.items():
            assert not leaks(value, output, fixed), f"{name} appears in the output"


@pytest.fixture
def scenario(tmp_path: Path) -> tuple[Path, Planted, dict[str, str]]:
    """target/app: a clone of a repository with history; target/notes: a
    folder outside git. Returns the target, the secrets, and commit ids."""
    planted = Planted()
    origin = Repo(tmp_path / "origin")
    origin.write(
        "config.py",
        "DEBUG = True\n"
        f'GITHUB_TOKEN = "{planted.token("committed", "github-token")}"\n'
        # Decoys: a placeholder, a reference to the environment, a hash.
        'API_KEY = "your_api_key_here_1234"\n'
        'DB_PASSWORD = os.environ["DB_PASSWORD"]\n'
        'cache_key = "3f2a9c0d8e7b6a5f4e3d2c1b0a998877"\n',
    )
    origin.write(
        "old.env", f"STRIPE_KEY={planted.token('removed', 'stripe-secret-key')}\n"
    )
    origin.write(".gitignore", ".env\n")
    first = origin.commit("first")
    (origin.path / "old.env").unlink()
    # config.py changes, keeping its token: two versions with one secret.
    with (origin.path / "config.py").open("a") as f:
        f.write("TIMEOUT = 30\n")
    removed = origin.commit("remove old.env")

    app = Repo.clone(origin, tmp_path / "target" / "app")
    app.write(
        "deploy/settings.yml",
        f"slack:\n  token: {planted.token('unpushed', 'slack-token')}\n",
    )
    unpushed = app.commit("settings")
    # The working tree: an ignored .env, an edit to a committed file, a
    # binary file, and a link out of the target.
    app.write(".env", f"AWS_KEY_ID={planted.token('ignored', 'aws-access-key-id')}\n")
    with (app.path / "config.py").open("a") as f:
        f.write(f'HF_TOKEN = "{planted.token("edited", "huggingface-token")}"\n')
    binary = FAKES["github-token"](planted.rng)
    planted.other("binary", binary)
    app.write("blob.bin", b"\0\1\2" + binary.encode() + b"\0")
    outside = tmp_path / "outside.txt"
    outside.write_text(f"{planted.token('outside', 'openai-api-key')}\n")
    os.symlink(outside, app.path / "linked.txt")
    # A folder that is not in any repository.
    notes = tmp_path / "target" / "notes"
    notes.mkdir()
    (notes / "token.txt").write_text(
        f"session: {planted.other('jwt', jwt(planted.rng))}\n"
    )
    (notes / "id_ed25519").write_text(
        pem("OPENSSH", planted.other("key", private_key_body(planted.rng)))
    )
    commits = {"first": first, "removed": removed, "unpushed": unpushed}
    return tmp_path / "target", planted, commits


def _scan(target: Path, history: bool = True) -> SecretScan:
    root = target.resolve()
    return secrets.scan(root, walk(root), history=history)


def test_each_secret_where_it_is(
    scenario: tuple[Path, Planted, dict[str, str]],
) -> None:
    target, _, commits = scenario
    scan = _scan(target)
    # app/config.py has two: one committed, one an uncommitted edit.
    by = {(f.path, f.rule): f for f in scan.findings}
    assert len(by) == len(scan.findings) == 7

    committed = by[("app/config.py", "github-token")]
    assert (committed.state, committed.line, committed.column) == ("committed", 2, 17)
    assert committed.commit == commits["first"] and committed.pushed is True
    assert committed.repository == "app"

    removed = by[("app/old.env", "stripe-secret-key")]
    assert (removed.state, removed.pushed) == ("history", True)
    assert removed.commit == commits["first"]
    assert "pushed (in history): revoke it" in removed.advice

    unpushed = by[("app/deploy/settings.yml", "slack-token")]
    assert (unpushed.state, unpushed.pushed) == ("committed", False)
    assert unpushed.commit == commits["unpushed"]
    assert "not pushed" in unpushed.advice

    edited = by[("app/config.py", "huggingface-token")]
    assert (edited.state, edited.line, edited.commit) == ("uncommitted", 7, None)
    ignored = by[("app/.env", "aws-access-key-id")]
    assert ignored.state == "uncommitted"
    assert "keep it out of git" in ignored.advice

    session = by[("notes/token.txt", "jwt")]
    key = by[("notes/id_ed25519", "private-key")]
    assert session.state == key.state == "file"
    assert session.repository is None and key.repository is None

    # Not found: decoys, the binary file (counted), the link's target.
    assert not [f for f in scan.findings if f.rule == "secret-assignment"]
    assert scan.skipped_binary >= 1
    assert not [f for f in scan.findings if f.path == "app/linked.txt"]
    [repo] = scan.repositories
    assert (repo.path, repo.commits, repo.missing, repo.remotes) == ("app", 3, 0, True)


def test_head_only(scenario: tuple[Path, Planted, dict[str, str]]) -> None:
    target, _, _ = scenario
    scan = _scan(target, history=False)
    rules = {(f.path, f.rule, f.state) for f in scan.findings}
    assert ("app/old.env", "stripe-secret-key", "history") not in rules
    assert ("app/config.py", "github-token", "committed") in rules
    # Pushed or not cannot be told from HEAD alone.
    assert all(f.pushed is None for f in scan.findings)
    assert scan.repositories[0].commits == 1


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = main(args)
    out = capsys.readouterr()
    return code, out.out + out.err


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_no_secret_in_any_output(
    scenario: tuple[Path, Planted, dict[str, str]],
    capsys: pytest.CaptureFixture[str],
    fmt: str,
) -> None:
    target, planted, _ = scenario
    code, output = _run(
        ["scan", str(target), "--no-advisories", "--format", fmt], capsys
    )
    assert code == EXIT_FINDINGS
    planted.assert_not_in(output)
    if fmt == "json":
        report = json.loads(output)
        assert report["summary"]["secrets"] == 7
        assert report["summary"]["secrets_failing"] == 5  # not the 2 uncommitted
        assert report["summary"]["secrets_by_state"] == {
            "committed": 2,
            "file": 2,
            "uncommitted": 2,
            "history": 1,
        }
    if fmt == "sarif":
        sarif = json.loads(output)
        jsonschema.validate(sarif, SCHEMA)
        results = sarif["runs"][0]["results"]
        assert {r["ruleId"] for r in results} == {
            "secret/github-token",
            "secret/stripe-secret-key",
            "secret/slack-token",
            "secret/huggingface-token",
            "secret/aws-access-key-id",
            "secret/jwt",
            "secret/private-key",
        }
        assert all(r["partialFingerprints"]["vulnscan/secret/v1"] for r in results)


def test_text_report(
    scenario: tuple[Path, Planted, dict[str, str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    target, _, commits = scenario
    _, text = _run(["scan", str(target), "--no-advisories"], capsys)
    assert "5 secrets, 5 failing" in text
    assert "2 in files not committed (not failing):" in text
    assert "ghp_… (40 characters); in HEAD, first in " + commits["first"][:10] in text


def test_only_uncommitted_secrets_pass(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Repo(tmp_path / "r")
    repo.write(".gitignore", ".env\n")
    repo.commit()
    repo.write(".env", f"TOKEN={FAKES['github-token'](random.Random(1))}\n")
    code, text = _run(["scan", str(repo.path), "--no-advisories"], capsys)
    assert code == EXIT_CLEAN
    assert "0 secrets, 0 failing" in text and "1 in files not committed" in text


def test_no_secrets_option(
    scenario: tuple[Path, Planted, dict[str, str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    target, _, _ = scenario
    code, output = _run(
        ["scan", str(target), "--no-advisories", "--no-secrets", "--format", "json"],
        capsys,
    )
    assert code == EXIT_CLEAN
    assert json.loads(output)["secrets"] == {"checked": False}


def _baseline(target: Path, entries: list[dict[str, str]]) -> None:
    lines = []
    for entry in entries:
        lines.append("[[accept]]")
        for key, value in entry.items():
            lines.append(
                f"{key} = {value}" if key == "expires" else f'{key} = "{value}"'
            )
    (target / ".vulnscan.toml").write_text("\n".join(lines) + "\n")


def test_accepting_a_secret_by_fingerprint(
    scenario: tuple[Path, Planted, dict[str, str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    target, planted, _ = scenario
    scan = _scan(target)
    failing = [f for f in scan.findings if f.state != "uncommitted"]
    later = (date.today() + timedelta(days=30)).isoformat()
    earlier = (date.today() - timedelta(days=1)).isoformat()
    _baseline(
        target,
        [
            {"secret": f.fingerprint, "reason": "a test fixture", "expires": later}
            for f in failing
        ]
        + [{"secret": "0" * 16, "reason": "long gone", "expires": later}],
    )
    code, text = _run(["scan", str(target), "--no-advisories"], capsys)
    assert code == EXIT_CLEAN
    assert "5 accepted (not failing):" in text
    assert "acceptance of secret 0000000000000000 matches no finding" in text
    planted.assert_not_in(text)

    _baseline(
        target,
        [{"secret": failing[0].fingerprint, "reason": "old", "expires": earlier}],
    )
    code, text = _run(["scan", str(target), "--no-advisories"], capsys)
    assert code == EXIT_FINDINGS
    assert f"acceptance of secret {failing[0].fingerprint} expired" in text


def test_a_baseline_holding_a_secret_is_refused_without_repeating_it(
    scenario: tuple[Path, Planted, dict[str, str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    target, planted, _ = scenario
    value = planted.values["committed"][0]
    _baseline(target, [{"secret": value, "reason": "oops", "expires": "2099-01-01"}])
    code, output = _run(["scan", str(target), "--no-advisories"], capsys)
    assert code == EXIT_ERROR
    assert "never the secret itself" in output
    assert not leaks(value, output, FIXED["github-token"])


def test_files_not_on_this_disk_are_not_read(
    scenario: tuple[Path, Planted, dict[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A file macOS has moved to iCloud is listed, not read (reading it
    would download it); whether git has a version of it is said."""
    target, _, _ = scenario
    real_lstat: Callable[..., os.stat_result] = os.lstat
    offline = {"app/.env", "app/config.py"}

    root = str(target.resolve())

    def lstat(path: str | Path) -> object:
        st = real_lstat(path)
        rel = os.path.relpath(str(path), root)  # (resolve() would call lstat)
        if rel in offline:
            return types.SimpleNamespace(
                st_mode=st.st_mode, st_size=st.st_size, st_flags=0x40000000
            )
        return st

    monkeypatch.setattr(os, "lstat", lstat)
    scan = _scan(target)
    assert dict(scan.offline) == {"app/.env": False, "app/config.py": True}
    paths = {(f.path, f.state) for f in scan.findings}
    assert ("app/.env", "uncommitted") not in paths  # not read
    assert ("app/config.py", "committed") in paths  # from git
    assert ("app/config.py", "uncommitted") not in paths


def test_head_not_on_this_disk_is_never_uncommitted(
    scenario: tuple[Path, Planted, dict[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When iCloud has moved HEAD's branch ref off the disk, which commit is
    checked out is not known. Secrets in history are then "in-git", and in
    the working tree "file": both fail. (The first version called every
    file in such a repository uncommitted, which never fails.)"""
    target, _, _ = scenario
    real_lstat: Callable[..., os.stat_result] = os.lstat
    root = str(target.resolve())
    # HEAD's branch, and HEAD's own reflog, both moved to iCloud.
    offline = {"app/.git/refs/heads/main", "app/.git/logs/HEAD"}

    def lstat(path: str | Path) -> object:
        st = real_lstat(path)
        if os.path.relpath(str(path), root) in offline:
            return types.SimpleNamespace(
                st_mode=st.st_mode, st_size=st.st_size, st_flags=0x40000000
            )
        return st

    monkeypatch.setattr(os, "lstat", lstat)
    scan = _scan(target)
    states = {(f.path, f.rule): f.state for f in scan.findings}
    assert states[("app/config.py", "github-token")] == "in-git"
    assert states[("app/old.env", "stripe-secret-key")] == "in-git"
    assert states[("app/.env", "aws-access-key-id")] == "file"
    assert "uncommitted" not in states.values()
    [repo] = scan.repositories
    assert any("HEAD's branch is not on this disk" in n for n in repo.notes)


def test_head_from_its_reflog(
    scenario: tuple[Path, Planted, dict[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HEAD itself and its branch moved to iCloud, its reflog still on
    disk: HEAD is read from the reflog, and every state is what it is when
    nothing is missing."""
    target, _, _ = scenario
    expected = {(f.path, f.rule): f.state for f in _scan(target).findings}
    real_lstat: Callable[..., os.stat_result] = os.lstat
    root = str(target.resolve())
    offline = {"app/.git/HEAD", "app/.git/refs/heads/main"}

    def lstat(path: str | Path) -> object:
        st = real_lstat(path)
        if os.path.relpath(str(path), root) in offline:
            return types.SimpleNamespace(
                st_mode=st.st_mode, st_size=st.st_size, st_flags=0x40000000
            )
        return st

    monkeypatch.setattr(os, "lstat", lstat)
    scan = _scan(target)
    assert {(f.path, f.rule): f.state for f in scan.findings} == expected
    [repo] = scan.repositories
    assert "HEAD read from its reflog: its ref is not on this disk" in repo.notes
