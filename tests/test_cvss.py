import itertools

import pytest
from cvss import CVSS3

from vulnscan.cvss import base_score, rating, roundup


@pytest.mark.parametrize(
    ("vector", "score", "severity"),
    [
        # Scores as published (NVD) for well-known vulnerabilities.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),  # Log4Shell
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            7.5,
            "high",
        ),  # ws, CVE-2024-37890
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "high"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3, "medium"),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "medium"),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "low"),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "none"),
        # Temporal and environmental metrics are allowed, and not scored.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:O", 7.5, "high"),
    ],
)
def test_known_scores(vector: str, score: float, severity: str) -> None:
    result = base_score(vector)
    assert result is not None
    assert (result.score, result.rating) == (score, severity)


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # A missing
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # AV twice
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # no such value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1",  # no such metric
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # no version prefix
    ],
)
def test_not_a_cvss_3_vector(vector: str) -> None:
    assert base_score(vector) is None


def test_roundup_as_the_specification_gives_it() -> None:
    assert roundup(4.02) == 4.1
    assert roundup(4.00) == 4.0
    # Plain ceil(x * 10) / 10 would give 4.1 here: 4.000000000000001 is
    # floating point noise, which the integer method absorbs.
    assert roundup(4.000000000000001) == 4.0
    assert rating(0.1) == "low" and rating(3.9) == "low" and rating(4.0) == "medium"
    assert (
        rating(6.9) == "medium" and rating(7.0) == "high" and rating(9.0) == "critical"
    )


METRICS = [
    ("AV", "NALP"),
    ("AC", "LH"),
    ("PR", "NLH"),
    ("UI", "NR"),
    ("S", "UC"),
    ("C", "HLN"),
    ("I", "HLN"),
    ("A", "HLN"),
]


def test_every_base_vector_scores_as_the_reference_library_does() -> None:
    """All 2,592 combinations of the eight base metrics, against the cvss
    package (used only here, to check against)."""
    checked = 0
    for values in itertools.product(*(choices for _, choices in METRICS)):
        vector = "CVSS:3.1/" + "/".join(
            f"{name}:{value}" for (name, _), value in zip(METRICS, values, strict=True)
        )
        ours = base_score(vector)
        assert ours is not None
        assert ours.score == float(CVSS3(vector).scores()[0]), vector
        checked += 1
    assert checked == 2592
