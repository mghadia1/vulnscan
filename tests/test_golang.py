from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscan.inventory.golang import parse_go_mod
from vulnscan.inventory.model import How

# Gatekeeper's go.mod, with a replace and a toolchain added.
GO_MOD = """\
module github.com/mghadia1/gatekeeper

go 1.27.1

toolchain go1.27.2

require (
	github.com/alicebob/miniredis/v2 v2.39.0
	github.com/redis/go-redis/v9 v9.23.0 // the client
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	"github.com/munnerz/goautoneg" v0.0.0-20191010083416-a7dc8b61c822 // indirect
)

require golang.org/x/sys v0.48.0 // indirect

replace github.com/cespare/xxhash/v2 => github.com/fork/xxhash/v2 v2.3.1
replace github.com/redis/go-redis/v9 v9.23.0 => ../go-redis

require not-two-words
"""


def test_a_go_mod() -> None:
    parsed = parse_go_mod(GO_MOD, "go.mod")
    rows = [(p.name, p.version, p.direct, p.local, p.line) for p in parsed.packages]
    assert rows == [
        ("github.com/alicebob/miniredis/v2", "v2.39.0", True, False, 8),
        ("github.com/redis/go-redis/v9", "v9.23.0", True, True, 9),
        ("github.com/fork/xxhash/v2", "v2.3.1", False, False, 13),
        (
            "github.com/munnerz/goautoneg",
            "v0.0.0-20191010083416-a7dc8b61c822",
            False,
            False,
            14,
        ),
        ("golang.org/x/sys", "v0.48.0", False, False, 17),
        ("stdlib", "1.27.2", True, False, 5),
    ]
    assert parsed.packages[-1].how is How.PINNED
    assert [p.line for p in parsed.problems] == [22]


def test_without_a_toolchain_the_standard_library_is_a_range() -> None:
    parsed = parse_go_mod("module x\n\ngo 1.24\n", "go.mod")
    [stdlib] = parsed.packages
    assert (stdlib.name, stdlib.version, stdlib.spec, stdlib.how) == (
        "stdlib",
        None,
        ">=1.24",
        How.DECLARED,
    )


MODULES = st.from_regex(r"[a-z]{1,5}\.(com|org)/[a-z]{1,5}(/v[2-9])?", fullmatch=True)
GO_VERSIONS = st.from_regex(r"v[0-9]\.[0-9]{1,2}\.[0-9]{1,2}", fullmatch=True)


@settings(max_examples=150)
@given(
    st.dictionaries(MODULES, st.tuples(GO_VERSIONS, st.booleans()), max_size=8),
    st.booleans(),
)
def test_generated_go_mods(requires: dict[str, tuple[str, bool]], block: bool) -> None:
    lines = ["module example.com/me", "", "go 1.27"]
    if block:
        lines.append("require (")
    for module, (version, indirect) in requires.items():
        entry = f"{module} {version}" + (" // indirect" if indirect else "")
        lines.append(f"\t{entry}" if block else f"require {entry}")
    if block:
        lines.append(")")
    parsed = parse_go_mod("\n".join(lines) + "\n", "go.mod")
    got = {
        p.name: (p.version, not p.direct) for p in parsed.packages if p.name != "stdlib"
    }
    assert got == requires
    assert parsed.problems == []


@given(st.text(max_size=300))
def test_any_text_never_crashes_or_invents_a_module(text: str) -> None:
    for package in parse_go_mod(text, "go.mod").packages:
        assert package.name == "stdlib" or package.name in text
