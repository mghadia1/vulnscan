import os
import stat
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscan.walk import SKIPPED_DIRS, VENV_MARKER, walk


def touch(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_lists_files_relative_and_sorted(tmp_path: Path) -> None:
    for name in ["b.txt", "a/z.txt", "a/b/c.txt", "pyproject.toml"]:
        touch(tmp_path / name)
    tree = walk(tmp_path)
    assert tree.files == ("a/b/c.txt", "a/z.txt", "b.txt", "pyproject.toml")
    assert tree.errors == ()


def test_skips_version_control_installed_packages_and_caches(tmp_path: Path) -> None:
    touch(tmp_path / "package-lock.json")
    touch(tmp_path / "node_modules/left-pad/package.json")
    touch(tmp_path / ".git/config")
    touch(tmp_path / "web/node_modules/x/package-lock.json")
    touch(tmp_path / "src/__pycache__/m.cpython-314.pyc")
    tree = walk(tmp_path)
    assert tree.files == ("package-lock.json",)
    assert tree.skipped == (
        ".git",
        "node_modules",
        "src/__pycache__",
        "web/node_modules",
    )


def test_a_virtual_environment_is_found_by_its_marker_and_not_walked(
    tmp_path: Path,
) -> None:
    touch(tmp_path / "env-with-any-name" / VENV_MARKER, "home = /usr/bin\n")
    touch(tmp_path / "env-with-any-name/lib/site-packages/x/requirements.txt")
    # Named like one, but no marker: an ordinary directory.
    touch(tmp_path / ".venv/requirements.txt")
    tree = walk(tmp_path)
    assert tree.environments == ("env-with-any-name",)
    assert tree.files == (".venv/requirements.txt",)


def test_links_are_recorded_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    touch(outside / "secret/package-lock.json")
    touch(outside / "notes.txt")
    repo = tmp_path / "repo"
    touch(repo / "go.mod")
    os.symlink(outside / "secret", repo / "linked-dir")
    os.symlink(outside / "notes.txt", repo / "linked-file")
    os.symlink(repo / "nowhere", repo / "dangling")
    tree = walk(repo)
    assert tree.files == ("go.mod",)
    assert tree.symlinks == ("dangling", "linked-dir", "linked-file")


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_an_unreadable_directory_is_reported_not_fatal(tmp_path: Path) -> None:
    touch(tmp_path / "ok.txt")
    locked = tmp_path / "locked"
    touch(locked / "inside.txt")
    locked.chmod(0)
    try:
        tree = walk(tmp_path)
    finally:
        locked.chmod(stat.S_IRWXU)
    assert tree.files == ("ok.txt",)
    assert len(tree.errors) == 1
    assert tree.errors[0].startswith("locked: ")


# Random trees: names drawn from a small set, including the skipped ones,
# so they collide and nest. The walk must find exactly the files not under
# a skipped directory or an environment, computed here independently.
NAMES = st.sampled_from(["a", "b", "src", "web", ".git", "node_modules", "__pycache__"])
FILES = st.lists(
    st.tuples(st.lists(NAMES, max_size=3), st.sampled_from(["x.txt", "go.mod"])),
    max_size=12,
)
ENVS = st.lists(st.lists(NAMES, min_size=1, max_size=2), max_size=2)


@settings(max_examples=150, deadline=None)
@given(files=FILES, envs=ENVS)
def test_finds_exactly_the_files_outside_skipped_places(
    tmp_path_factory: pytest.TempPathFactory,
    files: list[tuple[list[str], str]],
    envs: list[list[str]],
) -> None:
    root = tmp_path_factory.mktemp("tree")
    for parts in envs:
        touch(root.joinpath(*parts, VENV_MARKER))
    for parts, name in files:
        touch(root.joinpath(*parts, name))
    env_dirs = {tuple(parts) for parts in envs}

    def hidden(parts: tuple[str, ...]) -> bool:
        # Under a skipped directory, or under (or at) an environment.
        for i in range(1, len(parts) + 1):
            if parts[i - 1] in SKIPPED_DIRS or parts[:i] in env_dirs:
                return True
        return False

    expected = {"/".join(parts + [name]) for parts, name in files}
    expected |= {"/".join(parts + [VENV_MARKER]) for parts in envs}
    expected = {p for p in expected if not hidden(tuple(p.split("/")[:-1]))}
    assert set(walk(root).files) == expected
