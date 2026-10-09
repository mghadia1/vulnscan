import itertools

import packaging.version
import pytest
import semver as reference_semver
from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscan.versions import order, pep440, semver

# --- PEP 440 ---------------------------------------------------------------

# Strictly increasing, from the PEP's discussion of ordering (as packaging
# documents it).
PEP440_ORDER = [
    "1.0.dev456",
    "1.0a1",
    "1.0a2.dev456",
    "1.0a12.dev456",
    "1.0a12",
    "1.0b1.dev456",
    "1.0b2",
    "1.0b2.post345.dev456",
    "1.0b2.post345",
    "1.0rc1.dev456",
    "1.0rc1",
    "1.0",
    "1.0+abc.5",
    "1.0+abc.7",
    "1.0+5",
    "1.0.post456.dev34",
    "1.0.post456",
    "1.0.15",
    "1.1.dev1",
    "1!0.1",
]


def pep440_key(text: str) -> tuple[object, ...]:
    version = pep440.parse(text)
    assert version is not None, text
    return pep440.key(version)


def test_pep440_order() -> None:
    keys = [pep440_key(v) for v in PEP440_ORDER]
    for a, b in itertools.pairwise(keys):
        assert a < b


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("1.0", "1.0.0"),
        ("1.0-ALPHA.1", "1.0a1"),
        ("v1.0", "1.0"),
        ("1.0-1", "1.0.post1"),
        ("1.0c1", "1.0rc1"),
        ("1.0.preview2", "1.0rc2"),
        ("1.0.rev3", "1.0.post3"),
        ("1.0a", "1.0a0"),
        ("1.0+Ubuntu-1", "1.0+ubuntu.1"),
        # A separator may follow "dev" with no number (packaging agrees; I
        # first listed this as invalid).
        ("1.0-dev-", "1.0.dev0"),
    ],
)
def test_pep440_spellings_of_one_version(a: str, b: str) -> None:
    assert pep440_key(a) == pep440_key(b)


@pytest.mark.parametrize("text", ["", "1.0.", "a1.0", "1.0+", "1..0", "١.٠"])
def test_pep440_refuses(text: str) -> None:
    assert pep440.parse(text) is None


SEP = st.sampled_from(["", ".", "-", "_"])
NUM = st.integers(min_value=0, max_value=120).map(str) | st.sampled_from(["00", "007"])
PRE = st.sampled_from(
    ["a", "alpha", "b", "beta", "c", "rc", "pre", "preview", "A", "RC"]
)
POST = st.sampled_from(["post", "rev", "r", "POST"])


@st.composite
def pep440_like(draw: st.DrawFn) -> str:
    """Strings built from PEP 440's pieces, often valid, sometimes not."""
    text = draw(st.sampled_from(["", "v", "V", " "]))
    if draw(st.booleans()):
        text += draw(NUM) + "!"
    text += ".".join(draw(st.lists(NUM, min_size=1, max_size=4)))
    if draw(st.booleans()):
        text += (
            draw(SEP) + draw(PRE) + draw(SEP) + draw(st.sampled_from(["", "1", "12"]))
        )
    if draw(st.booleans()):
        if draw(st.booleans()):
            text += "-" + draw(NUM)
        else:
            text += (
                draw(SEP) + draw(POST) + draw(SEP) + draw(st.sampled_from(["", "3"]))
            )
    if draw(st.booleans()):
        text += draw(SEP) + "dev" + draw(st.sampled_from(["", "4"]))
    if draw(st.booleans()):
        text += "+" + draw(
            st.sampled_from(["abc", "5", "abc.5", "Ubuntu-1", "1_2", "x."])
        )
    if draw(st.integers(0, 9)) == 0:
        text += draw(st.sampled_from(["..", "-", "+", "!", "x"]))
    return text


def reference_pep440(text: str) -> packaging.version.Version | None:
    try:
        return packaging.version.Version(text)
    except packaging.version.InvalidVersion:
        return None


@settings(max_examples=2000)
@given(pep440_like())
def test_pep440_accepts_exactly_what_packaging_accepts(text: str) -> None:
    ours, theirs = pep440.parse(text), reference_pep440(text)
    assert (ours is None) == (theirs is None), text
    if ours is not None:
        assert str(ours) == str(theirs)  # normalised the same way


@settings(max_examples=2000)
@given(pep440_like(), pep440_like())
def test_pep440_orders_as_packaging_does(a: str, b: str) -> None:
    ra, rb = reference_pep440(a), reference_pep440(b)
    if ra is None or rb is None:
        return
    ka, kb = pep440_key(a), pep440_key(b)
    assert (ka < kb, ka == kb) == (ra < rb, ra == rb), (a, b)


# --- SemVer ----------------------------------------------------------------

SEMVER_ORDER = [
    "1.0.0-alpha",
    "1.0.0-alpha.1",
    "1.0.0-alpha.beta",
    "1.0.0-beta",
    "1.0.0-beta.2",
    "1.0.0-beta.11",
    "1.0.0-rc.1",
    "1.0.0",
    "1.0.1",
    "1.1.0",
    "2.0.0",
]


def semver_key(text: str) -> tuple[object, ...]:
    version = semver.parse(text)
    assert version is not None, text
    return semver.key(version)


def test_semver_order_from_the_spec() -> None:
    keys = [semver_key(v) for v in SEMVER_ORDER]
    for a, b in itertools.pairwise(keys):
        assert a < b
    assert semver_key("1.0.0+build.1") == semver_key("1.0.0+other")


@pytest.mark.parametrize(
    "text", ["1.0", "01.0.0", "1.0.0-", "1.0.0-01", "v1.0.0", "1.0.0+", "1.0.0-a..b"]
)
def test_semver_refuses(text: str) -> None:
    assert semver.parse(text) is None


IDENT = st.sampled_from(["alpha", "beta", "rc", "0", "1", "11", "2", "x-y", "01", "-"])


@st.composite
def semver_like(draw: st.DrawFn) -> str:
    text = ".".join(draw(NUM) for _ in range(draw(st.sampled_from([3, 3, 3, 2]))))
    if draw(st.booleans()):
        text += "-" + ".".join(draw(st.lists(IDENT, min_size=1, max_size=3)))
    if draw(st.booleans()):
        text += "+" + draw(st.sampled_from(["build.1", "sha.abc", "x"]))
    return text


@settings(max_examples=2000)
@given(semver_like())
def test_semver_accepts_exactly_what_the_reference_accepts(text: str) -> None:
    assert (semver.parse(text) is not None) == reference_semver.Version.is_valid(
        text
    ), text


@settings(max_examples=2000)
@given(semver_like(), semver_like())
def test_semver_orders_as_the_reference_does(a: str, b: str) -> None:
    if not (
        reference_semver.Version.is_valid(a) and reference_semver.Version.is_valid(b)
    ):
        return
    ka, kb = semver_key(a), semver_key(b)
    expected = reference_semver.Version.parse(a).compare(b)
    assert (ka > kb) - (ka < kb) == expected, (a, b)


# --- Go --------------------------------------------------------------------


def go_module_key(text: str) -> tuple[object, ...]:
    version = semver.from_go(text)
    assert version is not None, text
    return semver.key(version)


def test_go_module_versions() -> None:
    ordered = [
        "v0.0.0-20191010083416-a7dc8b61c822",  # pseudo-versions: a pre-release of 0.0.0
        "v0.0.0-20200101000000-abcdef123456",
        "v0.1.0",
        "v2.0.0+incompatible",  # build metadata: precedence as 2.0.0
        "v2.0.1",
    ]
    keys = [go_module_key(v) for v in ordered]
    for a, b in itertools.pairwise(keys):
        assert a < b
    assert go_module_key("v2.0.0+incompatible") == go_module_key("2.0.0")


@pytest.mark.parametrize(
    ("toolchain", "as_semver"),
    [
        ("go1.21rc2", "1.21.0-rc.2"),
        ("go1.9beta1", "1.9.0-beta.1"),
        ("1.24", "1.24.0"),
        ("1.27.2", "1.27.2"),
    ],
)
def test_go_toolchain_versions(toolchain: str, as_semver: str) -> None:
    version = semver.from_go_toolchain(toolchain)
    assert version is not None
    assert semver.key(version) == semver_key(as_semver)


def test_which_order_for_which_range() -> None:
    py, npm_order, go = order("PyPI", "x"), order("npm", "x"), order("Go", "x")
    assert py is not None and npm_order is not None and go is not None
    assert py("1.0") == py("1.0.0")  # PEP 440, not SemVer
    assert npm_order("1.0") is None
    assert go("v1.2.3") == go("1.2.3")
    stdlib = order("Go", "stdlib")
    assert stdlib is not None and stdlib("1.21rc2") is not None
    assert order("PyPI", "x", "GIT") is None
    assert order("crates.io", "x") is None
