import pytest
from hypothesis import given
from hypothesis import strategies as st

from vulnscan.inventory.pep508 import normalize, parse


@pytest.mark.parametrize(
    ("text", "name", "extras", "specs", "url", "marker", "pinned"),
    [
        ("requests==2.31.0", "requests", (), (("==", "2.31.0"),), None, None, "2.31.0"),
        ("foo===1.0", "foo", (), (("===", "1.0"),), None, None, "1.0"),
        ("foo==1.*", "foo", (), (("==", "1.*"),), None, None, None),
        (
            "fastapi>=0.115,<1",
            "fastapi",
            (),
            ((">=", "0.115"), ("<", "1")),
            None,
            None,
            None,
        ),
        (
            "psycopg[binary, pool] >= 3.2",
            "psycopg",
            ("binary", "pool"),
            ((">=", "3.2"),),
            None,
            None,
            None,
        ),
        (
            "foo (>=1.0, !=1.2)",
            "foo",
            (),
            ((">=", "1.0"), ("!=", "1.2")),
            None,
            None,
            None,
        ),
        (
            'foo==1.0; python_version < "3.9"',
            "foo",
            (),
            (("==", "1.0"),),
            None,
            'python_version < "3.9"',
            "1.0",
        ),
        (
            'pkg @ https://example.com/pkg-1.0.whl ; sys_platform == "linux"',
            "pkg",
            (),
            (),
            "https://example.com/pkg-1.0.whl",
            'sys_platform == "linux"',
            None,
        ),
        ("bare", "bare", (), (), None, None, None),
    ],
)
def test_parses(
    text: str,
    name: str,
    extras: tuple[str, ...],
    specs: tuple[tuple[str, str], ...],
    url: str | None,
    marker: str | None,
    pinned: str | None,
) -> None:
    req = parse(text)
    assert req is not None
    assert (req.name, req.extras, req.specifiers, req.url, req.marker) == (
        name,
        extras,
        specs,
        url,
        marker,
    )
    assert req.pinned == pinned


@pytest.mark.parametrize(
    "text", ["", "   ", ">=1.0", "foo>=", "foo bar", "foo[!]", "-e ."]
)
def test_refuses(text: str) -> None:
    assert parse(text) is None


def test_names_are_normalised_as_pep_503_says() -> None:
    assert normalize("Foo.Bar__baz-QUX") == "foo-bar-baz-qux"
    req = parse("Typing_Extensions>=4")
    assert req is not None and req.normalized == "typing-extensions"


NAMES = st.from_regex(r"[A-Za-z0-9]([A-Za-z0-9._-]{0,8}[A-Za-z0-9])?", fullmatch=True)
VERSIONS = st.from_regex(r"[0-9]{1,3}(\.[0-9]{1,3}){0,2}(\.post[0-9])?", fullmatch=True)
OPS = st.sampled_from(["==", "!=", ">=", "<=", "<", ">", "~=", "==="])
MARKERS = st.sampled_from(
    [None, 'python_version >= "3.10"', 'sys_platform == "win32"', "extra == 'dev'"]
)


@given(
    name=NAMES,
    extras=st.lists(NAMES, max_size=2),
    specs=st.lists(st.tuples(OPS, VERSIONS), max_size=3),
    marker=MARKERS,
    space=st.sampled_from(["", " "]),
)
def test_round_trip(
    name: str,
    extras: list[str],
    specs: list[tuple[str, str]],
    marker: str | None,
    space: str,
) -> None:
    text = name
    if extras:
        text += "[" + ",".join(extras) + "]"
    text += space + ",".join(op + space + version for op, version in specs)
    if marker:
        text += "; " + marker
    req = parse(text)
    assert req is not None, text
    assert req.name == name
    assert req.extras == tuple(extras)
    assert req.specifiers == tuple(specs)
    assert req.marker == marker
    pinned = len(specs) == 1 and specs[0][0] in ("==", "===")
    assert req.pinned == (specs[0][1] if pinned else None)


@given(st.text(max_size=60))
def test_any_text_is_a_requirement_or_none(text: str) -> None:
    req = parse(text)
    if req is not None:
        assert req.name in text
