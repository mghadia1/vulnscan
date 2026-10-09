import json
import os
import subprocess
import sys
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscan.inventory.model import How, Package
from vulnscan.inventory.pep508 import normalize
from vulnscan.inventory.python import (
    parse_poetry_lock,
    parse_pyproject,
    parse_requirements,
    parse_uv_lock,
    python_version,
    read_environment,
)


def summary(packages: list[Package]) -> list[tuple[str, str | None, str, int | None]]:
    return [(p.name, p.version, p.how.value, p.line) for p in packages]


REQUIREMENTS = """\
# a comment
Django==5.1.2  # pinned
requests>=2.31,<3
psycopg[binary]==3.2.3 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
typing_extensions==4.12.2; python_version < "3.13"
-r dev.txt
--requirement=more.txt
-c constraints.txt
--index-url https://example.com/simple
--require-hashes
-e git+https://github.com/x/mylib.git#egg=MyLib
pkg @ https://example.com/pkg-1.0-py3-none-any.whl
this is not a requirement
--made-up-option
"""


def test_requirements() -> None:
    parsed = parse_requirements(REQUIREMENTS, "requirements.txt")
    assert summary(parsed.packages) == [
        ("django", "5.1.2", "pinned", 2),
        ("requests", None, "declared", 3),
        ("psycopg", "3.2.3", "pinned", 4),
        ("typing-extensions", "4.12.2", "pinned", 7),
        ("mylib", None, "declared", 13),
        ("pkg", None, "declared", 14),
    ]
    by_name = {p.name: p for p in parsed.packages}
    assert by_name["requests"].spec == ">=2.31,<3"
    assert by_name["typing-extensions"].marker == 'python_version < "3.13"'
    assert by_name["mylib"].local and by_name["pkg"].local
    assert not by_name["django"].local
    assert parsed.includes == ["dev.txt", "more.txt"]
    assert [(p.line, p.message) for p in parsed.problems] == [
        (15, "not a requirement: this is not a requirement"),
        (16, "unknown option --made-up-option"),
    ]


def test_pyproject() -> None:
    text = """\
[build-system]
requires = ["setuptools>=69"]

[project]
name = "x"
dependencies = [
  "fastapi>=0.142",
  "uvicorn[standard]==0.34.0",
  "not a requirement !",
]

[project.optional-dependencies]
dev = ["pytest>=9"]

[dependency-groups]
lint = ["ruff==0.16.10", {include-group = "dev"}]
"""
    parsed = parse_pyproject(text, "pyproject.toml")
    assert [
        (p.name, p.version, p.spec, p.scope, p.group, p.line) for p in parsed.packages
    ] == [
        ("fastapi", None, ">=0.142", "runtime", None, 7),
        ("uvicorn", "0.34.0", None, "runtime", None, 8),
        ("pytest", None, ">=9", "optional", "dev", 13),
        ("ruff", "0.16.10", None, "dev", "lint", 16),
        ("setuptools", None, ">=69", "build", None, 2),
    ]
    assert all(p.direct for p in parsed.packages)
    assert [p.line for p in parsed.problems] == [9]


def test_pyproject_that_is_not_toml_is_a_problem() -> None:
    parsed = parse_pyproject("[project\n", "pyproject.toml")
    assert parsed.packages == []
    assert parsed.problems[0].message.startswith("not valid TOML")


UV_LOCK = """\
version = 1
requires-python = ">=3.12"

[[package]]
name = "anyio"
version = "4.6.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "idna" }]

[[package]]
name = "MyProject"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "fromgit"
version = "1.0"
source = { git = "https://github.com/x/y?rev=abc#abc" }
"""

POETRY_LOCK = """\
[[package]]
name = "certifi"
version = "2024.8.30"
optional = false
python-versions = ">=3.6"

[[package]]
name = "private"
version = "2.0"

[package.source]
type = "legacy"
url = "https://pypi.example.com/simple"
reference = "corp"

[[package]]
name = "mylib"
version = "0.1.0"

[package.source]
type = "directory"
url = "../mylib"
"""


def test_uv_lock() -> None:
    parsed = parse_uv_lock(UV_LOCK, "uv.lock")
    assert [(p.name, p.version, p.how, p.line, p.local) for p in parsed.packages] == [
        ("anyio", "4.6.0", How.LOCKED, 4, False),
        ("myproject", "0.1.0", How.LOCKED, 10, True),
        ("fromgit", "1.0", How.LOCKED, 15, True),
    ]


def test_poetry_lock() -> None:
    parsed = parse_poetry_lock(POETRY_LOCK, "poetry.lock")
    assert [(p.name, p.version, p.line, p.local) for p in parsed.packages] == [
        ("certifi", "2024.8.30", 1, False),
        ("private", "2.0", 7, False),  # a private index is still an index
        ("mylib", "0.1.0", 16, True),
    ]


def make_dist(site: Path, name: str, version: str, **extra: str) -> Path:
    dist = site / f"{name}-{version}.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text(
        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n\nlong text\n"
    )
    for file, text in extra.items():
        (dist / file).write_text(text)
    return dist


def test_an_environment(tmp_path: Path) -> None:
    env = tmp_path / ".venv"
    (env / "pyvenv.cfg").parent.mkdir(parents=True)
    (env / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.14.7\n")
    site = env / "lib/python3.14/site-packages"
    make_dist(site, "FastAPI", "0.142.0")
    url = json.dumps({"url": "file:///src/me", "dir_info": {"editable": True}})
    make_dist(site, "me", "0.1.0", **{"direct_url.json": url})
    vcs = json.dumps({"url": "https://github.com/x/y", "vcs_info": {"vcs": "git"}})
    make_dist(site, "fromgit", "1.0", **{"direct_url.json": vcs})
    wheel = json.dumps(
        {"url": "https://x.org/w-2.0-py3-none-any.whl", "archive_info": {}}
    )
    make_dist(site, "fromurl", "2.0", **{"direct_url.json": wheel})
    (site / "old_style-1.0.egg-info").mkdir()
    (site / "old_style-1.0.egg-info/PKG-INFO").write_text(
        "Name: old-style\nVersion: 1.0\n"
    )
    (site / "broken-1.0.dist-info").mkdir()  # no METADATA
    # Linux venvs link lib64 to lib: not read twice.
    os.symlink(env / "lib", env / "lib64")

    parsed = read_environment(tmp_path, ".venv")
    assert [(p.name, p.version, p.local) for p in parsed.packages] == [
        ("fastapi", "0.142.0", False),
        ("fromgit", "1.0", True),
        ("fromurl", "2.0", True),
        ("me", "0.1.0", True),
        ("old-style", "1.0", False),
    ]
    assert all(p.how is How.INSTALLED for p in parsed.packages)
    assert parsed.packages[0].path == (
        ".venv/lib/python3.14/site-packages/FastAPI-0.142.0.dist-info/METADATA"
    )
    assert [p.path.split("/")[-2] for p in parsed.problems] == ["broken-1.0.dist-info"]
    assert python_version(tmp_path, ".venv") == "3.14.7"


def test_links_out_of_an_environment_are_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    make_dist(outside / "python3.14/site-packages", "evil", "6.6.6")
    (outside / "PKG-INFO").write_text("Name: also-evil\nVersion: 1.0\n")
    repo = tmp_path / "repo"
    (repo / "env").mkdir(parents=True)
    (repo / "env/pyvenv.cfg").write_text("")
    os.symlink(outside, repo / "env/lib")  # the whole lib folder
    parsed = read_environment(repo, "env")
    assert parsed.packages == []

    (repo / "env/lib").unlink()
    site = repo / "env/lib/python3.14/site-packages"
    site.mkdir(parents=True)
    os.symlink(outside / "PKG-INFO", site / "linked-1.0.egg-info")
    # A linked folder: its METADATA is an ordinary file, so only the check
    # on the folder itself stops it.
    os.symlink(
        outside / "python3.14/site-packages/evil-6.6.6.dist-info",
        site / "evil-6.6.6.dist-info",
    )
    meta = make_dist(site, "ok", "1.0") / "METADATA"
    meta.unlink()
    os.symlink(outside / "PKG-INFO", meta)
    parsed = read_environment(repo, "env")
    assert parsed.packages == []
    assert [p.message for p in parsed.problems] == ["a link, not followed"] * 3


def test_a_real_environment_made_by_python(tmp_path: Path) -> None:
    """A venv made by `python -m venv`, read against what its own pip says."""
    env = tmp_path / "env"
    subprocess.run([sys.executable, "-m", "venv", str(env)], check=True)
    listed = subprocess.run(
        [str(env / "bin/python"), "-m", "pip", "list", "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    expected = {(normalize(d["name"]), d["version"]) for d in json.loads(listed.stdout)}
    parsed = read_environment(tmp_path, "env")
    top = {(p.name, p.version) for p in parsed.packages if p.scope is None}
    assert top == expected
    # What pip bundles (from its SBOM, when its version has one) is what
    # its own _vendor/vendor.txt pins.
    bundled = {
        (p.name, p.version) for p in parsed.packages if p.scope == "bundled in pip"
    }
    [vendor_txt] = list(env.glob("lib/python*/site-packages/pip/_vendor/vendor.txt"))
    pins = {
        (normalize(name), version)
        for name, _, version in (
            line.split("#")[0].strip().partition("==")
            for line in vendor_txt.read_text().splitlines()
        )
        if version
    }
    if list(env.glob("lib/python*/site-packages/pip/_vendor/bom.cdx.json")):
        assert bundled == pins
    else:
        assert bundled == set()
    assert (
        "pip",
        subprocess.run(
            [str(env / "bin/python"), "-c", "import pip; print(pip.__version__)"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
    ) in expected


# Generated requirements files: pins mixed with comments, blank lines,
# options, hashes on continuation lines. Exactly the pins come back, on
# the lines they start on.
NAMES = st.from_regex(r"[a-z][a-z0-9]{0,6}", fullmatch=True)
VERSIONS = st.from_regex(r"[0-9]{1,2}\.[0-9]{1,2}(\.[0-9])?", fullmatch=True)
NOISE = st.sampled_from(
    ["", "# just a comment", "--index-url https://x/simple", "--pre", "   "]
)


@settings(max_examples=200)
@given(
    entries=st.lists(
        st.tuples(NAMES, VERSIONS, st.booleans(), st.booleans(), NOISE), max_size=8
    )
)
def test_generated_requirements(
    entries: list[tuple[str, str, bool, bool, str]],
) -> None:
    lines: list[str] = []
    expected: list[tuple[str, str, int]] = []
    for name, version, hashed, commented, noise in entries:
        if noise:
            lines.append(noise)
        line = f"{name}=={version}"
        if commented:
            line += "  # why"
        expected.append((name, version, len(lines) + 1))
        if hashed:
            lines += [line + " \\", "    --hash=sha256:00ff"]
        else:
            lines.append(line)
    parsed = parse_requirements("\n".join(lines) + "\n", "r.txt")
    assert [(p.name, p.version, p.line) for p in parsed.packages] == expected
    assert parsed.problems == []


@given(st.text(max_size=300))
def test_any_text_never_crashes_or_invents_a_package(text: str) -> None:
    for parse in (
        parse_requirements,
        parse_pyproject,
        parse_uv_lock,
        parse_poetry_lock,
    ):
        parsed = parse(text, "f")
        for package in parsed.packages:
            assert package.name in normalize(text), (parse.__name__, package)


# pip's own preprocessing as the reference for how lines are joined and
# comments removed (pip is in every virtual environment; its internals are
# used here only to check against, never by VulnScan).
PIECES = st.sampled_from(
    ["pkg==1.0", " ", "#", "\\", "x", "--hash=sha256:ab", "# note", "a#b", "\t"]
)


@settings(max_examples=300)
@given(st.lists(st.lists(PIECES, max_size=5).map("".join), max_size=8))
def test_lines_are_joined_and_uncommented_as_pip_does(lines: list[str]) -> None:
    from pip._internal.req.req_file import preprocess

    from vulnscan.inventory.python import _logical_lines

    text = "\n".join(lines)
    assert _logical_lines(text) == list(preprocess(text))
