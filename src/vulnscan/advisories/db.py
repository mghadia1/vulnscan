"""The local advisory index: OSV's exports, read once, kept in SQLite.

A scan reads only this file: no network. ``vulnscan update`` fills it.

Per ecosystem, the whole export is replaced in one transaction: a build
that fails part-way leaves the previous data as it was. Withdrawn
advisories are left out. Of an advisory, only what a finding needs is kept
(its id, aliases, summary, severities, references, and the affected
entries of the ecosystems VulnScan reads); the long "details" text is not.
"""

import json
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from vulnscan.advisories.osv import Advisory, Affected, Range
from vulnscan.inventory.pep508 import normalize

ECOSYSTEMS = ("PyPI", "npm", "Go")

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshot (
    ecosystem TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    md5_checked INTEGER NOT NULL,
    last_modified TEXT,
    built TEXT NOT NULL,
    advisories INTEGER NOT NULL,
    withdrawn INTEGER NOT NULL,
    rejected INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS advisory (
    id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    modified TEXT NOT NULL,
    published TEXT,
    aliases TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    database_severity TEXT,
    refs TEXT NOT NULL,
    PRIMARY KEY (ecosystem, id)
) STRICT;
CREATE TABLE IF NOT EXISTS affected (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    advisory TEXT NOT NULL,
    package TEXT NOT NULL,
    ranges TEXT NOT NULL,
    versions TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS affected_by_name ON affected (ecosystem, name);
"""


@dataclass(frozen=True)
class Snapshot:
    ecosystem: str
    source: str
    bytes: int
    sha256: str
    md5_checked: bool
    last_modified: str | None
    built: str
    advisories: int
    withdrawn: int
    rejected: int


def key_name(ecosystem: str, name: str) -> str:
    """How a package name is looked up: Python names as PEP 503 normalises
    them (OSV writes "Django", an environment "django"); others as written."""
    return normalize(name) if ecosystem == "PyPI" else name


class Database:
    def __init__(self, path: Path, readonly: bool = False) -> None:
        """Opens (or creates) the index. ``readonly`` opens an existing one
        without ever writing to it, so it works on a read-only mount."""
        self.path = path
        if readonly:
            self._db = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.executescript(SCHEMA)

    def close(self) -> None:
        self._db.close()

    def replace(
        self,
        ecosystem: str,
        advisories: Iterable[Advisory | str],
        snapshot: Snapshot,
    ) -> Snapshot:
        """Replaces one ecosystem's advisories, all at once or not at all.
        ``advisories`` may hold strings: advisories that could not be read,
        counted as rejected."""
        counts = {"advisories": 0, "withdrawn": 0, "rejected": 0}
        with self._db:  # one transaction; rolled back if anything raises
            self._db.execute("DELETE FROM affected WHERE ecosystem = ?", (ecosystem,))
            self._db.execute("DELETE FROM advisory WHERE ecosystem = ?", (ecosystem,))
            for advisory in advisories:
                if isinstance(advisory, str):
                    counts["rejected"] += 1
                    continue
                if advisory.withdrawn:
                    counts["withdrawn"] += 1
                    continue
                counts["advisories"] += 1
                self._db.execute(
                    "INSERT OR REPLACE INTO advisory"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        advisory.id,
                        ecosystem,
                        advisory.modified,
                        advisory.published,
                        json.dumps(advisory.aliases),
                        advisory.summary,
                        json.dumps(advisory.severity),
                        advisory.database_severity,
                        json.dumps(advisory.references[:10]),
                    ),
                )
                self._db.executemany(
                    "INSERT INTO affected VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        (
                            ecosystem,
                            key_name(ecosystem, a.name),
                            advisory.id,
                            a.name,
                            json.dumps([[r.type, r.events] for r in a.ranges]),
                            json.dumps(a.versions),
                        )
                        for a in advisory.affected
                        if a.ecosystem == ecosystem
                    ],
                )
            final = Snapshot(**{**snapshot.__dict__, **counts})
            self._db.execute(
                "INSERT OR REPLACE INTO snapshot VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    final.ecosystem,
                    final.source,
                    final.bytes,
                    final.sha256,
                    int(final.md5_checked),
                    final.last_modified,
                    final.built,
                    final.advisories,
                    final.withdrawn,
                    final.rejected,
                ),
            )
        return final

    def snapshots(self) -> list[Snapshot]:
        rows = self._db.execute("SELECT * FROM snapshot ORDER BY ecosystem").fetchall()
        return [
            Snapshot(r[0], r[1], r[2], r[3], bool(r[4]), r[5], r[6], r[7], r[8], r[9])
            for r in rows
        ]

    def lookup(self, ecosystem: str, name: str) -> Iterator[tuple[Advisory, Affected]]:
        """Every advisory with an affected entry for this package."""
        rows = self._db.execute(
            """SELECT a.id, a.modified, a.published, a.aliases, a.summary,
                      a.severity, a.database_severity, a.refs,
                      f.package, f.ranges, f.versions
               FROM affected f JOIN advisory a
                 ON a.ecosystem = f.ecosystem AND a.id = f.advisory
               WHERE f.ecosystem = ? AND f.name = ?
               ORDER BY a.id""",
            (ecosystem, key_name(ecosystem, name)),
        )
        for row in rows:
            affected = Affected(
                ecosystem=ecosystem,
                name=row[8],
                ranges=tuple(
                    Range(kind, tuple((k, v) for k, v in events))
                    for kind, events in json.loads(row[9])
                ),
                versions=tuple(json.loads(row[10])),
            )
            advisory = Advisory(
                id=row[0],
                modified=row[1],
                published=row[2],
                withdrawn=None,
                aliases=tuple(json.loads(row[3])),
                summary=row[4],
                severity=tuple((k, v) for k, v in json.loads(row[5])),
                database_severity=row[6],
                references=tuple(json.loads(row[7])),
                affected=(affected,),
            )
            yield advisory, affected
