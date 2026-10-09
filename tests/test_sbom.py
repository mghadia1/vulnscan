"""Packages bundled inside other packages: package URLs, CycloneDX SBOMs,
and what an environment's reader finds under _vendor and in PEP 770's
.dist-info/sboms."""

import json
import os
import types
from pathlib import Path

import pytest

from vulnscan.inventory.model import Ecosystem
from vulnscan.inventory.python import read_environment
from vulnscan.inventory.sbom import components, purl


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("pkg:pypi/urllib3@2.7.0", ("pypi", "urllib3", "2.7.0", None)),
        ("pkg:npm/%40scope/name@1.0#lib", ("npm", "@scope/name", "1.0", "lib")),
        ("pkg:npm/@scope/name@1.0", ("npm", "@scope/name", "1.0", None)),
        ("pkg:npm/@scope/name", ("npm", "@scope/name", None, None)),
        (
            "pkg:golang/github.com/x/y@v1.2.3?type=module",
            ("golang", "github.com/x/y", "v1.2.3", None),
        ),
        ("pkg:PyPI/Foo@1", ("pypi", "Foo", "1", None)),
        ("pkg:pypi/", None),
        ("pypi/urllib3@1", None),
        ("pkg:nopath", None),
    ],
)
def test_package_urls(text: str, expected: object) -> None:
    assert purl(text) == expected


def _bom(*items: dict[str, object], nested: bool = False) -> str:
    comps: list[dict[str, object]] = list(items)
    if nested and comps:
        comps = [{**comps[0], "components": comps[1:]}]
    return json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": comps}
    )


def test_components() -> None:
    text = _bom(
        {"name": "pip", "type": "library"},  # no version, no purl: itself
        {
            "name": "CacheControl",
            "version": "0.14.4",
            "purl": "pkg:pypi/CacheControl@0.14.4",
        },
        {"name": "x", "version": "1", "purl": "pkg:npm/%40a/x@1"},
        {"name": "y", "version": "1", "purl": "pkg:golang/example.com/y@v1.0.0"},
        {"name": "zlib", "version": "1.3", "purl": "pkg:generic/zlib@1.3"},
        {"name": "libfoo", "version": "2.0"},  # versioned, no purl
        {"name": "dup", "version": "1", "purl": "pkg:pypi/CacheControl@0.14.4"},
    )
    found, unchecked = components(text)
    assert found == [
        (Ecosystem.PYPI, "cachecontrol", "0.14.4"),
        (Ecosystem.NPM, "@a/x", "1"),
        (Ecosystem.GO, "example.com/y", "v1.0.0"),
    ]
    assert unchecked == 2


def test_nested_components_and_the_distribution_itself() -> None:
    text = _bom(
        {
            "name": "PIL._imaging",
            "version": "12.3.0",
            "purl": "pkg:pypi/pillow@12.3.0#c-ext/PIL._imaging",
        },
        {"name": "urllib3", "version": "2.7.0", "purl": "pkg:pypi/urllib3@2.7.0"},
        nested=True,
    )
    found, _ = components(text, itself="Pillow")
    assert found == [(Ecosystem.PYPI, "urllib3", "2.7.0")]


@pytest.mark.parametrize("text", ["{}", "[]", '{"bomFormat": "SPDX"}', "not json"])
def test_not_cyclonedx(text: str) -> None:
    with pytest.raises(ValueError):
        components(text)


def _dist(site: Path, folder: str, name: str, version: str) -> Path:
    d = site / folder
    d.mkdir(parents=True)
    (d / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    )
    return d


@pytest.fixture
def env(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    site = root / ".venv/lib/python3.14/site-packages"
    (root / ".venv/pyvenv.cfg").parent.mkdir(parents=True)
    (root / ".venv/pyvenv.cfg").write_text("home = /x\n")
    _dist(site, "pip-26.0.dist-info", "pip", "26.0")
    (site / "pip/_vendor").mkdir(parents=True)
    (site / "pip/_vendor/bom.cdx.json").write_text(
        _bom(
            {"name": "pip"},
            {"name": "urllib3", "version": "2.7.0", "purl": "pkg:pypi/urllib3@2.7.0"},
        )
    )
    _dist(site, "setuptools-80.0.dist-info", "setuptools", "80.0")
    _dist(site / "setuptools/_vendor", "packaging-24.2.dist-info", "packaging", "24.2")
    pillow = _dist(site, "pillow-12.3.0.dist-info", "pillow", "12.3.0")
    (pillow / "sboms").mkdir()
    (pillow / "sboms/pillow.cdx.json").write_text(
        _bom(
            {
                "name": "PIL._webp",
                "version": "12.3.0",
                "purl": "pkg:pypi/pillow@12.3.0#c-ext/PIL._webp",
            },
            {
                "name": "libwebp",
                "version": "1.5.0",
                "purl": "pkg:generic/libwebp@1.5.0",
            },
        )
    )
    return root


def test_bundled_packages_in_an_environment(env: Path) -> None:
    parsed = read_environment(env, ".venv")
    found = {(p.name, p.version, p.scope) for p in parsed.packages}
    assert found == {
        ("pip", "26.0", None),
        ("urllib3", "2.7.0", "bundled in pip"),
        ("setuptools", "80.0", None),
        ("packaging", "24.2", "bundled in setuptools"),
        ("pillow", "12.3.0", None),
    }
    urllib3 = next(p for p in parsed.packages if p.name == "urllib3")
    assert urllib3.path.endswith("pip/_vendor/bom.cdx.json")
    # Bundled copies came from an index inside their bundler: not local.
    assert not any(p.local for p in parsed.packages if p.scope)
    assert [p.message for p in parsed.problems] == [
        "1 bundled components not checkable (not PyPI, npm or Go packages)"
    ]


def test_links_are_not_followed(env: Path, tmp_path: Path) -> None:
    site = env / ".venv/lib/python3.14/site-packages"
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "_vendor").mkdir(parents=True)
    (elsewhere / "_vendor/bom.cdx.json").write_text(
        _bom({"name": "a", "version": "1", "purl": "pkg:pypi/evil@1"})
    )
    os.symlink(elsewhere, site / "linked")
    # A real package folder whose _vendor is a link out of the repository.
    (site / "realpkg").mkdir()
    os.symlink(elsewhere / "_vendor", site / "realpkg/_vendor")
    parsed = read_environment(env, ".venv")
    assert "evil" not in {p.name for p in parsed.packages}


def test_a_broken_sbom_is_a_problem_not_a_crash(env: Path) -> None:
    site = env / ".venv/lib/python3.14/site-packages"
    (site / "pip/_vendor/bom.cdx.json").write_text("{not json")
    parsed = read_environment(env, ".venv")
    assert any("not read" in p.message for p in parsed.problems)
    assert "urllib3" not in {p.name for p in parsed.packages}


def test_metadata_not_on_this_disk_is_not_read(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bundled package's metadata that iCloud has moved off the disk is a
    problem named, not a download."""
    target = (
        env
        / ".venv/lib/python3.14/site-packages/setuptools/_vendor"
        / "packaging-24.2.dist-info/METADATA"
    )
    real_lstat = os.lstat

    def lstat(path: str | Path) -> object:
        st = real_lstat(path)
        if Path(path) == target:
            return types.SimpleNamespace(
                st_mode=st.st_mode, st_size=st.st_size, st_flags=0x40000000
            )
        return st

    monkeypatch.setattr(os, "lstat", lstat)
    parsed = read_environment(env, ".venv")
    assert "packaging" not in {p.name for p in parsed.packages}
    assert any(p.message == "not on this disk (iCloud)" for p in parsed.problems)
