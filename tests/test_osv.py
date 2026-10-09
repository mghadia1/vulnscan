from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from vulnscan.advisories.osv import (
    Advisory,
    Affected,
    Range,
    Verdict,
    evaluate,
    parse_advisory,
)

A, N, U = Verdict.AFFECTED, Verdict.NOT_AFFECTED, Verdict.UNKNOWN


def affected(
    ranges: list[tuple[str, list[tuple[str, str]]]],
    versions: tuple[str, ...] = (),
    ecosystem: str = "npm",
    name: str = "pkg",
) -> Affected:
    return Affected(
        ecosystem, name, tuple(Range(t, tuple(e)) for t, e in ranges), versions
    )


@pytest.mark.parametrize(
    ("events", "version", "verdict"),
    [
        # The schema's own examples.
        ([("introduced", "0")], "99.0.0", A),  # unfixed
        ([("introduced", "0"), ("fixed", "1.0.2")], "1.0.1", A),
        ([("introduced", "0"), ("fixed", "1.0.2")], "1.0.2", N),
        ([("introduced", "0"), ("fixed", "1.0.2")], "1.0.2-rc.1", A),  # before 1.0.2
        ([("introduced", "1.0.0"), ("last_affected", "2.0.0")], "2.0.0", A),
        ([("introduced", "1.0.0"), ("last_affected", "2.0.0")], "2.0.1", N),
        ([("introduced", "1.0.0"), ("last_affected", "2.0.0")], "0.9.0", N),
        ([("introduced", "0"), ("limit", "2.0.0")], "1.9.9", A),
        ([("introduced", "0"), ("limit", "2.0.0")], "2.0.0", N),
        # Two ranges in one list of events, given in any order.
        (
            [
                ("fixed", "1.1.4"),
                ("introduced", "1.1.0"),
                ("fixed", "1.0.2"),
                ("introduced", "0"),
            ],
            "1.0.5",
            N,
        ),
        (
            [
                ("fixed", "1.1.4"),
                ("introduced", "1.1.0"),
                ("fixed", "1.0.2"),
                ("introduced", "0"),
            ],
            "1.1.2",
            A,
        ),
        ([("introduced", "0"), ("fixed", "not-a-version")], "1.0.0", U),
    ],
)
def test_semver_ranges(
    events: list[tuple[str, str]], version: str, verdict: Verdict
) -> None:
    assert evaluate(version, affected([("SEMVER", events)])) is verdict


def test_python_ranges_use_pep_440() -> None:
    django = affected(
        [("ECOSYSTEM", [("introduced", "3.2"), ("fixed", "3.2.19")])], ecosystem="PyPI"
    )
    assert evaluate("3.2.18", django) is A
    assert evaluate("3.2.0", django) is A  # 3.2.0 is 3.2
    assert evaluate("3.2.19", django) is N
    assert evaluate("3.2a1", django) is N  # a pre-release comes before 3.2
    assert evaluate("not a version", django) is U


def test_the_explicit_list_decides_first() -> None:
    listed = affected(
        [("ECOSYSTEM", [("introduced", "3.2")])],
        versions=("1.0", "3.2a1"),
        ecosystem="PyPI",
    )
    assert evaluate("1.0.0", listed) is A  # equal to the listed "1.0"
    assert evaluate("3.2a1", listed) is A  # listed, though before the range
    assert evaluate("2.0", listed) is N


def test_git_ranges_need_the_list() -> None:
    commits = [("GIT", [("introduced", "a" * 40), ("fixed", "b" * 40)])]
    assert evaluate("1.0", affected(commits, versions=("1.0",), ecosystem="PyPI")) is A
    assert evaluate("2.0", affected(commits, versions=("1.0",), ecosystem="PyPI")) is N
    assert evaluate("2.0", affected(commits, ecosystem="PyPI")) is U


def test_go_modules_and_the_standard_library() -> None:
    module = affected(
        [("SEMVER", [("introduced", "0"), ("fixed", "0.23.0")])],
        ecosystem="Go",
        name="golang.org/x/net",
    )
    assert evaluate("v0.22.0", module) is A  # go.mod writes the "v"
    assert evaluate("v0.23.0", module) is N
    stdlib = affected(
        [("SEMVER", [("introduced", "0"), ("fixed", "1.21.0-rc.2")])],
        ecosystem="Go",
        name="stdlib",
    )
    assert evaluate("1.21rc1", stdlib) is A
    assert evaluate("1.21", stdlib) is N


def test_an_unknown_ecosystem_is_unknown() -> None:
    gem = affected([("ECOSYSTEM", [("introduced", "0")])], ecosystem="RubyGems")
    assert evaluate("1.0", gem) is U


# Random disjoint intervals [lo, hi) of major versions, written as one
# range's events in a random order: evaluation must say exactly which
# versions are inside.
@given(
    st.lists(st.integers(0, 40), min_size=2, max_size=10, unique=True).map(sorted),
    st.randoms(use_true_random=False),
    st.booleans(),
)
def test_intervals(bounds: list[int], rnd: Any, closed: bool) -> None:
    pairs = list(zip(bounds[::2], bounds[1::2], strict=False))
    end = "last_affected" if closed else "fixed"
    events = [("introduced", f"{lo}.0.0") for lo, _ in pairs]
    events += [(end, f"{hi}.0.0") for _, hi in pairs]
    rnd.shuffle(events)
    entry = affected([("SEMVER", events)])
    for v in range(0, 45):
        inside = any(lo <= v < hi or (closed and v == hi) for lo, hi in pairs)
        assert evaluate(f"{v}.0.0", entry) is (A if inside else N), (v, pairs)


GHSA: dict[str, Any] = {
    "schema_version": "1.7.4",
    "id": "GHSA-3h5v-q93c-6h6q",
    "modified": "2024-06-17T00:00:00Z",
    "published": "2024-06-17T00:00:00Z",
    "aliases": ["CVE-2024-37890"],
    "summary": "ws affected by a DoS when handling a request with many HTTP headers",
    "details": "A long text.",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
    ],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "ws"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "8.0.0"}, {"fixed": "8.17.1"}],
                }
            ],
            "database_specific": {"source": "x"},
        }
    ],
    "references": [
        {"type": "WEB", "url": "https://github.com/websockets/ws/issues/2230"}
    ],
    "database_specific": {"severity": "HIGH"},
}


def test_parse_an_advisory() -> None:
    advisory = parse_advisory(GHSA)
    assert isinstance(advisory, Advisory)
    assert advisory.aliases == ("CVE-2024-37890",)
    assert advisory.severity == (("CVSS_V3", GHSA["severity"][0]["score"]),)
    assert advisory.database_severity == "HIGH"
    assert advisory.references == ("https://github.com/websockets/ws/issues/2230",)
    assert not advisory.malicious
    [entry] = advisory.affected
    assert evaluate("8.17.0", entry) is A and evaluate("8.17.1", entry) is N


def test_summary_falls_back_to_the_first_line_of_details() -> None:
    advisory = parse_advisory({**GHSA, "summary": "", "details": "First line.\nMore."})
    assert isinstance(advisory, Advisory) and advisory.summary == "First line."


@pytest.mark.parametrize(
    "change",
    [
        {"id": 7},
        {"aliases": "CVE-1"},
        {"affected": {}},
        {"affected": [{"package": {"ecosystem": "npm"}}]},
        {"affected": [{"package": {"ecosystem": "npm", "name": "x"}, "versions": [1]}]},
        {
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "x"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0", "fixed": "1"}],
                        }
                    ],
                }
            ]
        },
        {
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "x"},
                    "ranges": [{"type": "SEMVER", "events": [{"broken": "1"}]}],
                }
            ]
        },
    ],
)
def test_malformed_advisories_are_refused_with_a_reason(change: dict[str, Any]) -> None:
    result = parse_advisory({**GHSA, **change})
    assert isinstance(result, str) and result
