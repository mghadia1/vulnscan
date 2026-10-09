"""Checks the range evaluation against OSV's own lists, on real advisories.

    PYTHONPATH=src python scripts/check_ranges.py PyPI.zip [npm.zip Go.zip]

(Each archive named after its ecosystem, as OSV names them.)

OSV adds to most advisories an explicit list of the affected versions,
worked out from the ranges against the registry's real releases. So every
listed version should come out AFFECTED when only the ranges are
evaluated. This counts, per ecosystem, how many do; and how many range
events and listed versions VulnScan's version ordering could not parse.
A listed version can also come from a GIT range (commits), which VulnScan
does not evaluate; those are counted apart.
"""

import json
import sys
import zipfile
from collections import Counter
from pathlib import Path

from vulnscan.advisories.osv import Affected, Verdict, in_range, parse_advisory
from vulnscan.versions import order


def check(archive: Path) -> None:
    # An export is one ecosystem's, but an advisory in it may also cover
    # packages of other ecosystems (RubyGems, Maven): those are not checked.
    ecosystem = archive.stem
    counts: Counter[str] = Counter()
    examples: dict[str, list[str]] = {}
    with zipfile.ZipFile(archive) as zf:
        for entry in zf.namelist():
            advisory = parse_advisory(json.loads(zf.read(entry)))
            if isinstance(advisory, str):
                counts["advisories not read"] += 1
                continue
            if advisory.withdrawn:
                counts["withdrawn"] += 1
                continue
            counts["advisories"] += 1
            for affected in advisory.affected:
                if affected.ecosystem != ecosystem:
                    continue
                for range_ in affected.ranges:
                    order_ = order(affected.ecosystem, affected.name, range_.type)
                    if order_ is None:
                        continue
                    for kind, text in range_.events:
                        special = (kind, text) in (("introduced", "0"), ("limit", "*"))
                        counts["events"] += 1
                        if not special and order_(text) is None:
                            counts["events not parsed"] += 1
                            examples.setdefault("event", []).append(
                                f"{advisory.id} {text}"
                            )
                if not affected.versions:
                    continue
                only_git = all(r.type == "GIT" for r in affected.ranges)
                ranges_only = Affected(
                    affected.ecosystem, affected.name, affected.ranges, ()
                )
                for version in affected.versions:
                    counts["listed versions"] += 1
                    if only_git or not affected.ranges:
                        counts["listed: no SEMVER/ECOSYSTEM range"] += 1
                        continue
                    verdicts = {
                        in_range(version, r, o)
                        for r in ranges_only.ranges
                        if r.type != "GIT"
                        and (o := order(affected.ecosystem, affected.name, r.type))
                    }
                    if Verdict.AFFECTED in verdicts:
                        counts["listed: affected"] += 1
                    elif Verdict.UNKNOWN in verdicts:
                        counts["listed: unknown"] += 1
                        examples.setdefault("unknown", []).append(
                            f"{advisory.id} {version}"
                        )
                    elif any(r.type == "GIT" for r in affected.ranges):
                        counts["listed: from a GIT range"] += 1
                    else:
                        counts["listed: NOT affected"] += 1
                        examples.setdefault("not", []).append(
                            f"{advisory.id} {version}"
                        )
    print(archive.name, dict(sorted(counts.items())))
    for kind, items in examples.items():
        print(f"  {kind}: {len(items)}, e.g. {items[:6]}")


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        check(Path(arg))
