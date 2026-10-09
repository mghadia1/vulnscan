"""CVSS v3 base scores, computed from the vector, as the CVSS v3.1
specification's section 7.1 defines them.

``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`` is 9.8, Critical. A vector
must name each of the eight base metrics exactly once; temporal and
environmental metrics may follow and are ignored (this is the base score,
as the advisories publish it). CVSS 3.0 vectors score the same way. CVSS
4.0 is not scored here: it is a different method (a table of 270
macro-vectors), so a 4.0-only advisory falls back to its source's own
severity word, and says so.
"""

import math
import re
from dataclasses import dataclass

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},  # with S:U; S:C below
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 0.0},  # not a weight: it changes the formula
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_OPTIONAL = {
    # Temporal and environmental metrics: allowed, not used.
    "E",
    "RL",
    "RC",
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MPR",
    "MUI",
    "MS",
    "MC",
    "MI",
    "MA",
}


@dataclass(frozen=True)
class Score:
    score: float
    rating: str  # "none", "low", "medium", "high", "critical"


def roundup(value: float) -> float:
    """The specification's Roundup (v3.1 Appendix A): the smallest number,
    to one decimal place, at or above the input, done in integers so that
    floating point cannot make 4.000000001 into 4.1."""
    whole = round(value * 100_000)
    if whole % 10_000 == 0:
        return whole / 100_000.0
    return (math.floor(whole / 10_000) + 1) / 10.0


def rating(score: float) -> str:
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def parse(vector: str) -> dict[str, str] | None:
    """The metrics of a CVSS 3.0 or 3.1 vector, or None if it is not one."""
    parts = vector.strip().split("/")
    if not re.fullmatch(r"CVSS:3\.[01]", parts[0]):
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        name, sep, value = part.partition(":")
        if not sep or name in metrics:
            return None
        if name in _WEIGHTS:
            if value not in _WEIGHTS[name]:
                return None
        elif name not in _OPTIONAL:
            return None
        metrics[name] = value
    if not all(name in metrics for name in _WEIGHTS):
        return None
    return metrics


def base_score(vector: str) -> Score | None:
    """The base score of a CVSS 3.0 or 3.1 vector, or None if it is not one."""
    m = parse(vector)
    if m is None:
        return None
    changed = m["S"] == "C"
    iss = 1 - (1 - _WEIGHTS["C"][m["C"]]) * (1 - _WEIGHTS["I"][m["I"]]) * (
        1 - _WEIGHTS["A"][m["A"]]
    )
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (_PR_CHANGED if changed else _WEIGHTS["PR"])[m["PR"]]
    exploitability = (
        8.22
        * _WEIGHTS["AV"][m["AV"]]
        * _WEIGHTS["AC"][m["AC"]]
        * pr
        * _WEIGHTS["UI"][m["UI"]]
    )
    if impact <= 0:
        score = 0.0
    elif changed:
        score = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = roundup(min(impact + exploitability, 10))
    return Score(score, rating(score))
