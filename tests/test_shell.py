"""Reading a RUN line's commands, and finding downloads run as code."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscan.containers.shell import piped_downloads, pipelines, program


def test_pipelines_and_words() -> None:
    found = pipelines("a 'b c' \"d $(e f)\" | g && h; i || j & k\nl")
    shape = [[c.words for c in p] for p in found]
    assert shape == [
        [["a", "b c", "d $(e f)"], ["g"]],
        [["h"]],
        [["i"]],
        [["j"]],
        [["k"]],
        [["l"]],
    ]
    assert found[0][0].inner == ["e f"]


def test_comments_and_continuations() -> None:
    assert [[c.words for c in p] for p in pipelines("a \\\n b # c | d")] == [
        [["a", "b"]]
    ]
    assert [[c.words for c in p] for p in pipelines("a#b")] == [[["a#b"]]]


def test_program() -> None:
    def prog(text: str) -> str | None:
        return program(pipelines(text)[0][0])

    assert prog("/usr/bin/curl -fsSL x") == "curl"
    assert prog("sudo -E bash -s") == "bash"
    assert prog("DEBIAN_FRONTEND=noninteractive env -i sh") == "sh"


@pytest.mark.parametrize(
    ("text", "how"),
    [
        ("curl -fsSL https://x/install.sh | sh", "curl piped into sh"),
        ("curl -fsSL https://x | sudo -E bash -s -- --yes", "curl piped into bash"),
        ("wget -qO- https://x|/bin/sh", "wget piped into sh"),
        ("curl x | tee log | python3 -", "curl piped into python3"),
        ("bash <(curl -s https://x)", "bash given curl's output"),
        ('sh -c "$(curl -fsSL https://x)"', "sh given curl's output"),
        ('eval "$(wget -O - https://x)"', "eval given wget's output"),
        ("sh -c 'curl x | bash'", "curl piped into bash"),
        ("apt-get update && curl x | sh && rm -rf /x", "curl piped into sh"),
        ("echo `curl -s x | sh`", "curl piped into sh"),
    ],
)
def test_downloads_run_as_code(text: str, how: str) -> None:
    assert how in piped_downloads(text)


@pytest.mark.parametrize(
    "text",
    [
        "curl -fsSL -o install.sh https://x && sha256sum -c sums && sh install.sh",
        "curl x | tar xz",
        "curl x | gpg --verify",
        "echo curl | sh",
        "curl --version",
        "apt-get install -y curl",
        "echo $(( 1 + 2 )) | sh",
        "'curl x | sh'",  # a quoted string, not a pipeline
        "pip install requests | tee log",
    ],
)
def test_not_downloads_run_as_code(text: str) -> None:
    assert piped_downloads(text) == []


@settings(max_examples=500, deadline=None)
@given(st.text(max_size=300))
def test_any_text(text: str) -> None:
    piped_downloads(text)
