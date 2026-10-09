"""The YAML reader against PyYAML (used only here): every scalar read as a
string, merge keys applied, on generated documents in every style PyYAML
writes, on hand-written anchors, merges and block scalars, and on real
Compose files; and what it refuses."""

import re
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscan.containers.yamlsub import YamlError, load, plain

DATA = Path(__file__).parent / "data" / "compose"


class StrLoader(yaml.SafeLoader):
    """PyYAML with every plain scalar a string, and merge keys applied."""


StrLoader.yaml_implicit_resolvers = {}
StrLoader.add_implicit_resolver(
    "tag:yaml.org,2002:merge", re.compile(r"^(?:<<)$"), ["<"]
)


def reference(text: str) -> object:
    return yaml.load(text, Loader=StrLoader)  # noqa: S506 (a safe loader)


def same(text: str) -> None:
    assert plain(load(text)) == reference(text), text


class Literal(yaml.SafeDumper):
    pass


class Folded(yaml.SafeDumper):
    pass


def _block(style: str) -> Callable[[yaml.SafeDumper, str], yaml.ScalarNode]:
    def represent(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
        return dumper.represent_scalar(
            "tag:yaml.org,2002:str", value, style=style if "\n" in value else None
        )

    return represent


Literal.add_representer(str, _block("|"))
Folded.add_representer(str, _block(">"))

text_values = st.text(
    alphabet=st.sampled_from(list("abc xyz019-_:#'\"\\/.,[]{}&*!|>%@`\n\t~?")),
    max_size=20,
)
keys = st.text(alphabet="abcdefghij_-0123456789", min_size=1, max_size=8)
values = st.recursive(
    text_values,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(keys, children, max_size=4)
    ),
    max_leaves=25,
)


@settings(max_examples=400, deadline=None)
@given(
    data=st.dictionaries(keys, values, min_size=1, max_size=5),
    flow=st.sampled_from([False, None, True]),
    indent=st.sampled_from([2, 4]),
    dumper=st.sampled_from([yaml.SafeDumper, Literal, Folded]),
)
def test_documents_pyyaml_writes(
    data: dict[str, object], flow: bool | None, indent: int, dumper: type
) -> None:
    text = yaml.dump(
        data,
        Dumper=dumper,
        default_flow_style=flow,
        indent=indent,
        width=10**6,
        allow_unicode=True,
        sort_keys=False,
    )
    try:
        mine = plain(load(text))
    except YamlError:
        # Refused, never misread: PyYAML writes long quoted strings over
        # several lines, which is outside the subset.
        return
    assert mine == reference(text) == data, text


one_line_values = st.recursive(
    st.text(
        alphabet=st.sampled_from(list("abc xyz019-_:#'\"\\/.,[]{}&*!|>%@`~?")),
        max_size=20,
    ),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(keys, children, max_size=4)
    ),
    max_leaves=25,
)


@settings(max_examples=400, deadline=None)
@given(
    data=st.dictionaries(keys, one_line_values, min_size=1, max_size=5),
    flow=st.sampled_from([False, None, True]),
    indent=st.sampled_from([2, 4]),
)
def test_documents_without_line_breaks_are_never_refused(
    data: dict[str, object], flow: bool | None, indent: int
) -> None:
    """Strings without line breaks are never written over several lines,
    so nothing here is outside the subset: every document is compared."""
    text = yaml.dump(
        data,
        Dumper=yaml.SafeDumper,
        default_flow_style=flow,
        indent=indent,
        width=10**6,
        allow_unicode=True,
        sort_keys=False,
    )
    assert plain(load(text)) == reference(text) == data, text


any_keys = st.text(
    alphabet=st.sampled_from(list("abc xyz019-_:#'\"\\/.,[]{}&*!|>%@`\n\t~?")),
    min_size=1,
    max_size=12,
)


@settings(max_examples=400, deadline=None)
@given(
    data=st.dictionaries(
        any_keys,
        st.recursive(
            text_values,
            lambda children: (
                st.lists(children, max_size=3)
                | st.dictionaries(any_keys, children, max_size=3)
            ),
            max_leaves=15,
        ),
        min_size=1,
        max_size=4,
    ),
    flow=st.sampled_from([False, None, True]),
)
def test_keys_with_any_characters_are_read_right_or_refused(
    data: dict[str, object], flow: bool | None
) -> None:
    """Keys full of YAML's own characters, which PyYAML quotes or writes as
    "? " keys: read exactly, or refused. (This found "? " keys inside { }
    being read as text, and a bare "*" crashing the reader.)"""
    text = yaml.dump(
        data,
        Dumper=yaml.SafeDumper,
        default_flow_style=flow,
        width=10**6,
        allow_unicode=True,
        sort_keys=False,
    )
    try:
        mine = plain(load(text))
    except YamlError:
        return
    assert mine == reference(text) == data, text


@settings(max_examples=200, deadline=None)
@given(shared=st.dictionaries(keys, text_values, min_size=1, max_size=3))
def test_shared_objects_become_anchors_and_aliases(shared: dict[str, str]) -> None:
    data = {"a": shared, "b": [shared, {"c": shared}]}
    text = yaml.dump(data, Dumper=yaml.SafeDumper, sort_keys=False, width=10**6)
    assert "&id001" in text and "*id001" in text
    try:
        mine = plain(load(text))
    except YamlError:
        return  # a multi-line quoted string: refused, never misread
    assert mine == reference(text) == data


@pytest.mark.parametrize(
    "text",
    [
        # Merge keys: one source, a list (earlier wins), the mapping's own
        # keys win, written before or after the merge.
        "base: &b\n  x: 1\n  y: 2\nc:\n  <<: *b\n  y: 3\n",
        "a: &a {x: 1, y: 1}\nb: &b {y: 2, z: 2}\nc:\n  <<: [*a, *b]\n",
        "a: &a\n  x: 1\nc:\n  x: 0\n  <<: *a\n",
        "x-svc: &svc\n  image: redis\n  ports:\n    - '6379:6379'\nservices:\n"
        "  a:\n    <<: *svc\n  b:\n    <<: *svc\n    image: valkey\n",
        # Block scalars, every chomping, blank lines, more-indented lines.
        "a: |\n  one\n  two\n",
        "a: |-\n  one\n\n  two\n\n",
        "a: |+\n  one\n\n\nb: x\n",
        "a: >\n  one\n  two\n\n  three\n    indented\n  four\n",
        "a: >-\n  folded\n  text\n",
        "a: >+\n  keep\n\n",
        "a: |\n\n  after a blank\n",
        "- |\n  in a list\n- >\n  folded\n  too\n",
        "a: |\n  # not a comment\n  b: not a key\n",
        # Sequences at their key's indentation, items that are mappings.
        "a:\n- x\n- y\nb: z\n",
        "a:\n  - k: 1\n    m: 2\n  - k: 3\n",
        "- - nested\n  - list\n- [flow, list]\n",
        "a: [1, [2, 3], {b: c}]\nd: {e: [f, g], 'h i': \"j\"}\n",
        "a: [one,\n  two,\n  three]\n",
        "a: {x: 1,\n    y: 2}\n",
        "a: []\nb: {}\nc: ''\nd: \"\"\ne:\n",
        # Comments and quoting.
        "# top\na: b # end\n# between\nc: 'd # e'\nf: \"g\\th\"\n",
        'a: it\'s\nb: \'it\'\'s\'\nc: "say \\"hi\\""\nd: "\\u00e9\\x41"\n',
        "a: http://x:80/y?z#w\nb: 8080:80\nc: ~\nd: true\n",
        "'quoted key': 1\n\"another\": 2\n",
        "---\na: b\n",
        "a: plain text\n  continued here\nb: c\n",
        "a: &x value\nb: *x\n",
        "a: -?\nb: ?x\nc: :y\nd: -1\n",  # indicators that start plain text
        "0]: {'0': 09}\na}b: [c]\n",  # brackets inside plain keys
        "- &item\n  k: v\n- *item\n",
    ],
)
def test_hand_written(text: str) -> None:
    same(text)


@pytest.mark.parametrize("name", sorted(p.name for p in DATA.glob("*.yaml")))
def test_real_compose_files(name: str) -> None:
    same((DATA / name).read_text())


@pytest.mark.parametrize(
    "text",
    [
        "a: !reset []\n",  # a tag
        "a: 1\n---\nb: 2\n",  # two documents
        "a: 1\na: 2\n",  # a key twice
        "a:\n\tb: 1\n",  # a tab for indentation
        "a: 'one\n  two'\n",  # a quoted string over two lines
        "a: |2\n   x\n",  # an explicit indentation
        "? complex\n: key\n",
        "a: *nowhere\n",
        "a: [1, 2\n",  # never closed
        "a: b: c\n",
        "a: 1\n  b: 2\n",  # more indented, after a value
        "%YAML 1.2\n---\na: 1\n",
        "a:\n  <<: plain\n",  # merging something that is not a mapping
        "{? a : b}\n",  # a "? " key inside { }
        "{*}\n",  # an alias with no name
        "[* , a]\n",
    ],
)
def test_refused(text: str) -> None:
    with pytest.raises(YamlError):
        load(text)


def test_lines() -> None:
    root = load(
        "services:\n  db:\n    image: postgres\n    ports:\n      - '5432:5432'\n"
    )
    assert root is not None
    db = root.get("services")
    assert db is not None
    service = db.get("db")
    assert service is not None
    assert service.line == 3  # a mapping starts where its first key is
    image = service.get("image")
    assert image is not None and image.line == 3
    ports = service.get("ports")
    assert ports is not None and isinstance(ports.value, list)
    assert ports.value[0].line == 5


def test_empty_documents() -> None:
    assert load("") is None
    assert load("# only a comment\n\n") is None


@settings(max_examples=1000, deadline=None)
@given(
    st.text(max_size=300)
    | st.text(alphabet=list("ab1 :-[]{}*&!|>'\"#,?\n"), max_size=120)
)
def test_any_text_is_read_or_refused(text: str) -> None:
    try:
        load(text)
    except YamlError:
        pass
