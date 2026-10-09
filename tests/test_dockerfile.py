"""The Dockerfile parser: on the hard cases, exactly as BuildKit parses
them (BuildKit's answers recorded in tests/data/buildkit, and compared
live when the BuildKit tool has been built); words and ENV/ARG pairs;
any text read without a crash."""

import json
import random
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscan.containers.dockerfile import (
    DockerfileError,
    assignments,
    parse,
    words,
)

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "tests/data/buildkit/cases.json").read_text())
sys.path.insert(0, str(ROOT / "scripts"))
import check_dockerfile_parser as reference  # noqa: E402


def as_buildkit(text: str) -> object:
    """Ours, in the shape the recorded BuildKit answers have."""
    return json.loads(json.dumps(reference.mine(text)))


@pytest.mark.parametrize("name", sorted(CASES))
def test_as_buildkit_parses_it(name: str) -> None:
    text, buildkit = CASES[name]
    assert as_buildkit(text) == buildkit


@pytest.mark.skipif(not reference.TOOL.exists(), reason="BuildKit tool not built")
def test_generated_dockerfiles_against_buildkit_itself() -> None:
    rng = random.Random(9)
    compared = 0
    for _ in range(200):
        text = reference.generated(rng)
        theirs = reference.theirs(text)
        if theirs == "error":
            continue  # BuildKit rejects its arguments: it cannot be built
        assert reference.mine(text) == theirs, text
        compared += 1
    assert compared > 150


def test_instructions() -> None:
    dockerfile = parse(
        "# syntax=docker/dockerfile:1\n"
        "ARG BASE=python:3.14-slim\n"
        "FROM --platform=$BUILDPLATFORM ${BASE} AS build\n"
        'RUN --mount=type=cache,target=/root/.cache pip install "x>=1"\n'
        'CMD ["python", "-m", "x"]\n'
    )
    assert dockerfile.directives == {"syntax": "docker/dockerfile:1"}
    arg, from_, run, cmd = dockerfile.instructions
    assert (arg.keyword, arg.rest, arg.line) == ("ARG", "BASE=python:3.14-slim", 2)
    assert from_.flag("platform") == "$BUILDPLATFORM"
    assert from_.rest == "${BASE} AS build"
    assert run.flag("mount") == "type=cache,target=/root/.cache"
    assert run.exec_form is None and run.rest == 'pip install "x>=1"'
    assert cmd.exec_form == ("python", "-m", "x")
    assert run.flag("missing") is None


def test_bad_escape_directive() -> None:
    with pytest.raises(DockerfileError):
        parse("# escape=x\nFROM a\n")


def test_unterminated_heredoc() -> None:
    with pytest.raises(DockerfileError):
        parse("RUN <<EOF\necho\n")


def test_words() -> None:
    assert words("a \"b c\" 'd e' f\\ g") == ["a", "b c", "d e", "f g"]
    assert words('"say \\"hi\\""') == ['say "hi"']
    assert words("x=`y", escape="`") == ["x=y"]


def test_assignments() -> None:
    assert assignments('A=1 B="two words" C=') == [
        ("A", "1"),
        ("B", "two words"),
        ("C", ""),
    ]
    assert assignments("NAME") == [("NAME", None)]  # ARG with no default
    assert assignments("PATH /usr/bin:/bin") == [("PATH", "/usr/bin:/bin")]
    assert assignments("GREETING hello world") == [("GREETING", "hello world")]


@settings(max_examples=500, deadline=None)
@given(st.text(max_size=400))
def test_any_text_is_read_or_refused(text: str) -> None:
    try:
        parse(text)
    except DockerfileError:
        pass
