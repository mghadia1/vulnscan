"""The hand-written git reader, checked against git itself: every object
read the same as ``git cat-file`` gives it (loose, packed, both kinds of
delta), every commit's files the same as ``git ls-tree``, on fixed and
random histories."""

import os
import random
import zlib
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from vulnscan.git import (
    GitError,
    MissingObject,
    Repository,
    apply_delta,
    blob_id,
    parse_commit,
    walk_history,
)

from helpers import Repo, body, needs_git

pytestmark = needs_git


def _history(repo: Repo, commits: int = 12, seed: int = 0) -> list[str]:
    """Files added, edited a little (so packs hold deltas), removed and
    renamed, over a number of commits, with a branch and a tag."""
    rng = random.Random(seed)
    base = "\n".join(body(rng, 60) for _ in range(200))
    shas = []
    for n in range(commits):
        lines = base.split("\n")
        lines[rng.randrange(len(lines))] = body(rng, 60)
        base = "\n".join(lines)
        repo.write("big.txt", base)
        repo.write(f"dir/sub/file{n % 3}.txt", f"version {n}\n")
        if n == 4:
            (repo.path / "dir/sub/file0.txt").unlink()
        if n == 6:
            repo.write("bin.dat", bytes(range(256)) * 4)
            # A link is not a file: its target is not scanned as content.
            os.symlink("big.txt", repo.path / "link.txt")
        shas.append(repo.commit(f"commit {n}"))
        if n == 5:
            repo.git("branch", "side")
            repo.git("tag", "-a", "v1", "-m", "a tag")
    return shas


def _same_objects(repo: Repo) -> int:
    theirs = repo.objects()
    mine = Repository.open(repo.path / ".git")
    try:
        assert set(mine.object_ids()) == set(theirs)
        for sha, (kind, data) in theirs.items():
            assert mine.read(sha) == (kind, data), sha
    finally:
        mine.close()
    return len(theirs)


def test_loose_objects_read_as_git_reads_them(tmp_path: Path) -> None:
    repo = Repo(tmp_path / "r")
    _history(repo)
    assert not list((repo.path / ".git/objects/pack").glob("*.pack"))
    assert _same_objects(repo) > 40


@pytest.mark.parametrize("offset_deltas", [True, False])
def test_packed_objects_with_deltas(tmp_path: Path, offset_deltas: bool) -> None:
    """Both delta kinds: OFS_DELTA (git's default) and REF_DELTA (asked
    for with repack.useDeltaBaseOffset=false)."""
    repo = Repo(tmp_path / "r")
    _history(repo, commits=20)
    flag = "true" if offset_deltas else "false"
    repo.git("-c", f"repack.useDeltaBaseOffset={flag}", "repack", "-adf", "-q")
    assert not [
        p for p in (repo.path / ".git/objects").iterdir() if len(p.name) == 2
    ], "all objects packed"
    verify = repo.git(
        "verify-pack", "-v", *map(str, (repo.path / ".git/objects/pack").glob("*.idx"))
    )
    assert b"chain length" in verify, "the pack holds deltas"
    assert _same_objects(repo) > 60


def test_history_matches_ls_tree(tmp_path: Path) -> None:
    repo = Repo(tmp_path / "r")
    shas = _history(repo)
    git = Repository.open(repo.path / ".git")
    history = walk_history(git)
    assert history.commits == len(shas)
    assert history.head == shas[-1]
    assert history.missing == 0
    # Every (path, blob) of every commit, and the first commit to have it.
    expected: dict[tuple[str, str], str] = {}
    for sha in shas:  # oldest first
        for pair in repo.files(sha):
            expected.setdefault(pair, sha)
    found = {(o.path, o.blob): o for o in history.occurrences}
    assert set(found) == set(expected)
    for pair, first in expected.items():
        assert found[pair].first_commit == first
    head = repo.files("HEAD")
    assert {pair for pair, o in found.items() if o.in_head} == head
    # Only HEAD:
    only_head = walk_history(git, everything=False)
    assert only_head.commits == 1
    assert {(o.path, o.blob) for o in only_head.occurrences} == head
    git.close()


@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    steps=st.lists(
        st.tuples(
            st.sampled_from(["write", "delete", "commit", "branch", "checkout"]),
            st.sampled_from(["a.txt", "d/b.txt", "d/e/c.txt", "f.txt"]),
            st.binary(max_size=200),
        ),
        min_size=1,
        max_size=25,
    ),
    pack=st.booleans(),
)
def test_random_histories(
    tmp_path_factory: pytest.TempPathFactory,
    steps: list[tuple[str, str, bytes]],
    pack: bool,
) -> None:
    """Random edits, commits and branches: the reader's (path, blob) pairs,
    first commits and HEAD files are git's."""
    repo = Repo(tmp_path_factory.mktemp("random") / "r")
    branches = 0
    for action, name, content in steps:
        if action == "write":
            repo.write(name, content)
        elif action == "delete" and (repo.path / name).exists():
            (repo.path / name).unlink()
        elif action == "commit":
            repo.commit()
        elif action == "branch":
            repo.commit()  # a branch needs a commit to point at
            branches += 1
            repo.git("branch", f"b{branches}")
        elif action == "checkout" and branches:
            repo.commit()  # keep the working tree's changes
            repo.git("checkout", "-q", f"b{branches}")
    repo.commit()
    if pack:
        repo.git("repack", "-adf", "-q")
    commits = (
        repo.git("rev-list", "--all", "--reverse", "--date-order").decode().split()
    )
    # git's committer times tie within a second here, so "first" is
    # checked as "some commit that has it, no later than any other".
    times = {
        sha: int(repo.git("show", "-s", "--format=%ct", sha).decode())
        for sha in commits
    }
    having: dict[tuple[str, str], list[str]] = {}
    for sha in commits:
        for pair in repo.files(sha):
            having.setdefault(pair, []).append(sha)
    git = Repository.open(repo.path / ".git")
    history = walk_history(git)
    git.close()
    found = {(o.path, o.blob): o for o in history.occurrences}
    assert set(found) == set(having)
    for pair, shas in having.items():
        assert found[pair].first_commit in shas
        assert times[found[pair].first_commit] == min(times[s] for s in shas)
    assert {p for p, o in found.items() if o.in_head} == repo.files("HEAD")


def test_pushed_follows_remote_tracking_refs(tmp_path: Path) -> None:
    origin = Repo(tmp_path / "origin")
    origin.write("a.txt", "one")
    first = origin.commit()
    local = Repo.clone(origin, tmp_path / "clone")
    local.write("b.txt", "two")
    second = local.commit()
    git = Repository.open(local.path / ".git")
    history = walk_history(git)
    git.close()
    assert history.remotes
    by_path = {o.path: o for o in history.occurrences}
    assert by_path["a.txt"].first_commit == first and by_path["a.txt"].pushed
    assert by_path["b.txt"].first_commit == second and not by_path["b.txt"].pushed


def test_pushed_even_when_first_seen_unpushed(tmp_path: Path) -> None:
    """Content first committed on a local branch, and later in a commit that
    was pushed (by someone else, say): it is out, so it is pushed."""
    origin = Repo(tmp_path / "origin")
    origin.write("base.txt", "x")
    origin.commit()
    local = Repo.clone(origin, tmp_path / "clone")
    local.git("checkout", "-q", "-b", "local")
    local.write("a.txt", "the same content")
    first = local.commit()  # unpushed, and earlier
    origin.commit()
    origin.write("a.txt", "the same content")
    origin.commit()
    local.git("fetch", "-q")
    git = Repository.open(local.path / ".git")
    history = walk_history(git)
    git.close()
    [a] = [o for o in history.occurrences if o.path == "a.txt"]
    assert a.first_commit == first
    assert a.pushed


def test_shallow_clone_stops_where_its_history_does(tmp_path: Path) -> None:
    origin = Repo(tmp_path / "origin")
    _history(origin, commits=5)
    clone = tmp_path / "clone"
    origin.git("clone", "-q", "--depth", "1", f"file://{origin.path}", str(clone))
    git = Repository.open(clone / ".git")
    history = walk_history(git)
    git.close()
    assert history.commits == 1
    assert history.missing == 0


def test_sha256_repositories_are_named_not_misread(tmp_path: Path) -> None:
    repo = Repo(tmp_path / "r", "--object-format=sha256")
    repo.write("a.txt", "x")
    repo.commit()
    with pytest.raises(GitError, match="SHA-256"):
        Repository.open(repo.path / ".git")


def test_links_under_git_are_not_followed(tmp_path: Path) -> None:
    repo = Repo(tmp_path / "r")
    repo.write("a.txt", "x")
    repo.commit()
    elsewhere = Repo(tmp_path / "elsewhere")
    elsewhere.write("secret.txt", "y")
    elsewhere_commit = elsewhere.commit()
    (tmp_path / "ref").write_text(elsewhere_commit + "\n")
    os.symlink(tmp_path / "ref", repo.path / ".git/refs/heads/linked")
    git = Repository.open(repo.path / ".git")
    assert "refs/heads/linked" not in git.refs()
    git.close()


def test_a_damaged_object_is_an_error_not_a_wrong_answer(tmp_path: Path) -> None:
    repo = Repo(tmp_path / "r")
    repo.write("a.txt", "the content")
    repo.commit()
    sha = blob_id(b"the content")
    path = repo.path / ".git/objects" / sha[:2] / sha[2:]
    path.chmod(0o644)
    path.write_bytes(zlib.compress(b"blob 11\0not content"))
    git = Repository.open(repo.path / ".git")
    with pytest.raises(GitError, match="does not match its name"):
        git.read(sha)
    path.write_bytes(b"not zlib at all")
    with pytest.raises(GitError):
        git.read(sha)
    with pytest.raises(MissingObject):
        git.read("0" * 40)
    git.close()


def test_blob_id_is_gits() -> None:
    # git hash-object of "hello\n", a well-known value.
    assert blob_id(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_delta_instructions() -> None:
    base = bytes(range(256)) * 300  # 76,800 bytes
    # A copy with no size bytes copies 0x10000; an insert of 3 bytes.
    header = _varint(len(base)) + _varint(0x10000 + 3)
    assert apply_delta(base, header + bytes([0x80, 3]) + b"xyz") == (
        base[:0x10000] + b"xyz"
    )
    # Copy 5 bytes from offset 300 (0x012C: two offset bytes, one size byte).
    copy = bytes([0x80 | 0x01 | 0x02 | 0x10, 0x2C, 0x01, 0x05])
    assert apply_delta(base, _varint(len(base)) + _varint(5) + copy) == base[300:305]
    with pytest.raises(GitError, match="reserved"):
        apply_delta(base, _varint(len(base)) + _varint(1) + bytes([0]))
    with pytest.raises(GitError, match="past the end"):
        apply_delta(b"abc", _varint(3) + _varint(10) + bytes([0x90, 10]))
    with pytest.raises(GitError, match="base"):
        apply_delta(b"abc", _varint(4) + _varint(1) + bytes([1]) + b"x")


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def test_commit_headers() -> None:
    data = (
        b"tree " + b"a" * 40 + b"\n"
        b"parent " + b"b" * 40 + b"\n"
        b"parent " + b"c" * 40 + b"\n"
        b"author A <a@x> 1 +0000\n"
        b"committer C D <c@x> 1700000123 -0130\n"
        b"gpgsig -----BEGIN PGP SIGNATURE-----\n \n -----END PGP SIGNATURE-----\n"
        b"\n"
        b"tree " + b"f" * 40 + b" in the message is not a header\n"
    )
    commit = parse_commit("d" * 40, data)
    assert commit.tree == "a" * 40
    assert commit.parents == ("b" * 40, "c" * 40)
    assert commit.time == 1700000123
