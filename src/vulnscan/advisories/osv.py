"""OSV advisories: the parts VulnScan uses, checked, and whether one affects
a version.

The evaluation is the OSV schema's own (its "Evaluation" section): a
version is affected if it is in the advisory's explicit ``versions`` list,
or in one of its ranges. A range's events are sorted by version and walked
in order: an "introduced" at or below the version makes it vulnerable, a
"fixed" at or below it makes it not, a "last_affected" below it makes it
not; "limit" events cap the whole range. "introduced": "0" is below every
version, "limit": "*" above every one.

Where the answer cannot be known here, it is UNKNOWN, never a guess: a
version that does not parse in the ecosystem's ordering, an event that does
not, or a GIT range (commits, which need the repository) with no explicit
versions list to go by.
"""

from dataclasses import dataclass
from enum import StrEnum

from vulnscan.versions import Key, Order, order


class Verdict(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not affected"
    UNKNOWN = "unknown"


EVENT_KINDS = ("introduced", "fixed", "last_affected", "limit")


@dataclass(frozen=True)
class Range:
    type: str  # SEMVER, ECOSYSTEM or GIT
    events: tuple[tuple[str, str], ...]  # (kind, version), as written


@dataclass(frozen=True)
class Affected:
    ecosystem: str
    name: str
    ranges: tuple[Range, ...]
    versions: tuple[str, ...]


@dataclass(frozen=True)
class Advisory:
    id: str
    modified: str
    published: str | None
    withdrawn: str | None
    aliases: tuple[str, ...]
    summary: str
    severity: tuple[tuple[str, str], ...]  # (type, CVSS vector)
    database_severity: str | None  # GHSA's own word: LOW, MODERATE, HIGH, CRITICAL
    references: tuple[str, ...]
    affected: tuple[Affected, ...]

    @property
    def malicious(self) -> bool:
        """OSV's MAL- advisories: a package published to do harm, not a bug."""
        return self.id.startswith("MAL-")


def _strings(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        return None
    return tuple(value)


def _summary(data: dict[str, object]) -> str:
    summary = data.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary.strip()
    details = data.get("details")
    if isinstance(details, str) and details.strip():
        first = details.strip().splitlines()[0]
        return first[:200] + ("…" if len(first) > 200 else "")
    return ""


def parse_advisory(data: object) -> Advisory | str:
    """An advisory, or a message saying why this is not one."""
    if not isinstance(data, dict):
        return "not an object"
    id_, modified = data.get("id"), data.get("modified")
    if not isinstance(id_, str) or not id_ or not isinstance(modified, str):
        return "no id or modified"
    aliases = _strings(data.get("aliases", []))
    if aliases is None:
        return f"{id_}: aliases is not a list of strings"
    severity: list[tuple[str, str]] = []
    for item in data.get("severity", []) or []:
        if isinstance(item, dict):
            kind, score = item.get("type"), item.get("score")
            if isinstance(kind, str) and isinstance(score, str):
                severity.append((kind, score))
    database = data.get("database_specific")
    database_severity = database.get("severity") if isinstance(database, dict) else None
    references = tuple(
        ref["url"]
        for ref in data.get("references", []) or []
        if isinstance(ref, dict) and isinstance(ref.get("url"), str)
    )
    affected: list[Affected] = []
    raw_affected = data.get("affected", [])
    if not isinstance(raw_affected, list):
        return f"{id_}: affected is not a list"
    for item in raw_affected:
        if not isinstance(item, dict):
            return f"{id_}: an affected entry is not an object"
        package = item.get("package")
        if not isinstance(package, dict):
            continue  # an entry about something other than a package
        ecosystem, name = package.get("ecosystem"), package.get("name")
        if not isinstance(ecosystem, str) or not isinstance(name, str):
            return f"{id_}: a package without an ecosystem or a name"
        versions = _strings(item.get("versions", []))
        if versions is None:
            return f"{id_}: versions is not a list of strings"
        ranges: list[Range] = []
        for raw in item.get("ranges", []) or []:
            if not isinstance(raw, dict) or not isinstance(raw.get("type"), str):
                return f"{id_}: a range without a type"
            events: list[tuple[str, str]] = []
            for event in raw.get("events", []) or []:
                if not isinstance(event, dict) or len(event) != 1:
                    return f"{id_}: an event must have exactly one field"
                [(kind, value)] = event.items()
                if kind not in EVENT_KINDS or not isinstance(value, str):
                    return f"{id_}: an unknown event {kind!r}"
                events.append((kind, value))
            ranges.append(Range(raw["type"], tuple(events)))
        affected.append(Affected(ecosystem, name, tuple(ranges), versions))
    published, withdrawn = data.get("published"), data.get("withdrawn")
    return Advisory(
        id=id_,
        modified=modified,
        published=published if isinstance(published, str) else None,
        withdrawn=withdrawn if isinstance(withdrawn, str) else None,
        aliases=aliases,
        summary=_summary(data),
        severity=tuple(severity),
        database_severity=database_severity
        if isinstance(database_severity, str)
        else None,
        references=references,
        affected=tuple(affected),
    )


# Sort keys wrapped so that "0" (below everything) and "*" (above
# everything) compare with real versions: (0,), (1, key), (2,).
_LOWEST: tuple[object, ...] = (0,)
_HIGHEST: tuple[object, ...] = (2,)


def _event_key(kind: str, text: str, order_: Order) -> tuple[object, ...] | None:
    if kind == "introduced" and text == "0":
        return _LOWEST
    if kind == "limit" and text == "*":
        return _HIGHEST
    key = order_(text)
    return None if key is None else (1, key)


def in_range(version: str, range_: Range, order_: Order) -> Verdict:
    """The OSV evaluation of one SEMVER or ECOSYSTEM range."""
    key: Key | None = order_(version)
    if key is None:
        return Verdict.UNKNOWN
    v = (1, key)
    events: list[tuple[tuple[object, ...], str]] = []
    for kind, text in range_.events:
        event_key = _event_key(kind, text, order_)
        if event_key is None:
            return Verdict.UNKNOWN
        events.append((event_key, kind))
    limits = [k for k, kind in events if kind == "limit"]
    if limits and not any(v < k for k in limits):
        return Verdict.NOT_AFFECTED
    vulnerable = False
    for event_key, kind in sorted(events, key=lambda e: e[0]):
        if kind == "introduced" and v >= event_key:
            vulnerable = True
        elif kind == "fixed" and v >= event_key:
            vulnerable = False
        elif kind == "last_affected" and v > event_key:
            vulnerable = False
    return Verdict.AFFECTED if vulnerable else Verdict.NOT_AFFECTED


def evaluate(version: str, affected: Affected) -> Verdict:
    """Whether ``version`` of ``affected``'s package is affected."""
    equal = order(affected.ecosystem, affected.name)
    key = equal(version) if equal is not None else None
    for listed in affected.versions:
        # "1.0" and "1.0.0" are one Python version: equal by the ordering.
        if listed == version or (
            key is not None and equal is not None and equal(listed) == key
        ):
            return Verdict.AFFECTED
    unknown = False
    for range_ in affected.ranges:
        if range_.type == "GIT":
            # Commits: only the explicit versions list can say; without
            # one, nothing can be said.
            unknown = unknown or not affected.versions
            continue
        order_ = order(affected.ecosystem, affected.name, range_.type)
        verdict = (
            Verdict.UNKNOWN if order_ is None else in_range(version, range_, order_)
        )
        if verdict is Verdict.AFFECTED:
            return verdict
        unknown = unknown or verdict is Verdict.UNKNOWN
    return Verdict.UNKNOWN if unknown else Verdict.NOT_AFFECTED
