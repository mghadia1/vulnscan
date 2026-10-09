import json
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscan.inventory.model import How
from vulnscan.inventory.npm import parse_package_json, parse_package_lock

# Shaped like a real npm 10 lockfile with workspaces (SyncBoard's): the
# project, its workspace folders, links to them, and registry packages.
LOCK: dict[str, Any] = {
    "name": "app",
    "version": "0.1.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {
            "name": "app",
            "version": "0.1.0",
            "workspaces": ["server"],
            "devDependencies": {"vite": "^8.0.0"},
        },
        "server": {
            "name": "@app/server",
            "version": "0.1.0",
            "dependencies": {"ws": "^8.22.0", "@redis/client": "^6.3.0"},
        },
        "node_modules/@app/server": {"resolved": "server", "link": True},
        "node_modules/@redis/client": {
            "version": "6.3.0",
            "resolved": "https://registry.npmjs.org/@redis/client/-/client-6.3.0.tgz",
            "dependencies": {"cluster-key-slot": "1.1.2"},
        },
        "node_modules/cluster-key-slot": {"version": "1.1.2"},
        "node_modules/vite": {"version": "8.3.3", "dev": True},
        "node_modules/fsevents": {"version": "2.3.3", "dev": True, "optional": True},
        "node_modules/ws": {"version": "8.22.0"},
        "node_modules/vite/node_modules/ws": {"version": "7.5.10", "dev": True},
        "node_modules/aliased": {"name": "real-name", "version": "1.0.0"},
        "node_modules/from-git": {
            "version": "0.0.1",
            "resolved": "git+ssh://git@github.com/x/y.git#abc",
        },
        "node_modules/maybe": {"version": "3.0.0", "devOptional": True},
    },
}


def test_a_lockfile() -> None:
    text = json.dumps(LOCK, indent=2)
    parsed = parse_package_lock(text, "package-lock.json")
    assert parsed.problems == []
    rows = [(p.name, p.version, p.direct, p.scope, p.local) for p in parsed.packages]
    assert rows == [
        ("@redis/client", "6.3.0", True, "runtime", False),
        ("cluster-key-slot", "1.1.2", False, "runtime", False),
        ("vite", "8.3.3", True, "dev", False),
        ("fsevents", "2.3.3", False, "dev", False),
        ("ws", "8.22.0", True, "runtime", False),
        ("ws", "7.5.10", False, "dev", False),  # a second copy, nested
        ("real-name", "1.0.0", False, "runtime", False),
        ("from-git", "0.0.1", False, "runtime", True),
        ("maybe", "3.0.0", False, "dev", False),
    ]
    assert all(p.how is How.LOCKED for p in parsed.packages)
    # Lines point at each package's key, as npm prints the file.
    lines = text.splitlines()
    for p in parsed.packages:
        assert p.line is not None and '": {' in lines[p.line - 1]


def test_lockfile_version_1_is_named_not_misread() -> None:
    old = {"lockfileVersion": 1, "dependencies": {"ws": {"version": "8.0.0"}}}
    parsed = parse_package_lock(json.dumps(old), "package-lock.json")
    assert parsed.packages == []
    assert "version 1" in parsed.problems[0].message


def test_broken_lockfiles_are_problems() -> None:
    for text in ["{", "[]", '{"lockfileVersion": 3}']:
        parsed = parse_package_lock(text, "p")
        assert parsed.packages == [] and len(parsed.problems) == 1
    missing = {"lockfileVersion": 3, "packages": {"node_modules/x": {}}}
    parsed = parse_package_lock(json.dumps(missing), "p")
    assert parsed.problems[0].message == "node_modules/x has no version"


def test_a_package_json_without_a_lockfile() -> None:
    manifest = {
        "dependencies": {
            "express": "^4.21.0",
            "lodash": "4.17.21",
            "mine": "file:../mine",
        },
        "devDependencies": {"typescript": "~5.6.0"},
    }
    parsed = parse_package_json(json.dumps(manifest, indent=2), "package.json")
    assert [
        (p.name, p.version, p.spec, p.how, p.scope, p.local) for p in parsed.packages
    ] == [
        ("express", None, "^4.21.0", How.DECLARED, "runtime", False),
        ("lodash", "4.17.21", None, How.PINNED, "runtime", False),
        ("mine", None, "file:../mine", How.DECLARED, "runtime", True),
        ("typescript", None, "~5.6.0", How.DECLARED, "dev", False),
    ]


# Generated lockfiles: every registry package comes back, once, with its
# version; the project, workspaces and links never do.
PACKAGE_NAMES = st.from_regex(r"(@[a-z]{1,4}/)?[a-z][a-z0-9-]{0,6}", fullmatch=True)
SEMVER = st.from_regex(r"[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}", fullmatch=True)


@settings(max_examples=150)
@given(st.dictionaries(PACKAGE_NAMES, SEMVER, max_size=10))
def test_generated_lockfiles(installed: dict[str, str]) -> None:
    packages: dict[str, Any] = {"": {"name": "root", "version": "1.0.0"}}
    packages["ws1"] = {"name": "ws1", "version": "0.0.0"}
    packages["node_modules/ws1"] = {"resolved": "ws1", "link": True}
    for name, version in installed.items():
        packages[f"node_modules/{name}"] = {"version": version}
    text = json.dumps({"lockfileVersion": 3, "packages": packages}, indent=2)
    parsed = parse_package_lock(text, "p")
    assert sorted((p.name, p.version) for p in parsed.packages) == sorted(
        installed.items()
    )


JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=8),
    lambda inner: (
        st.lists(inner, max_size=3)
        | st.dictionaries(st.text(max_size=20), inner, max_size=4)
    ),
    max_leaves=20,
)


@given(JSON)
def test_any_json_never_crashes_or_invents_a_package(value: object) -> None:
    for wrapped in (value, {"lockfileVersion": 3, "packages": value}):
        text = json.dumps(wrapped)
        for parse in (parse_package_lock, parse_package_json):
            for package in parse(text, "p").packages:
                assert json.dumps(package.name)[1:-1] in text
