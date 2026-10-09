"""Advisory data: where it lives, how it is updated, and how a package
version is looked up in it."""

import json
import os
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from vulnscan.advisories.db import ECOSYSTEMS, Database, Snapshot
from vulnscan.advisories.fetch import EXPORT_URL, download, file_info
from vulnscan.advisories.osv import Advisory, Verdict, evaluate, parse_advisory

__all__ = [
    "ECOSYSTEMS",
    "Database",
    "Match",
    "Snapshot",
    "data_dir",
    "lookup",
    "update",
]

DB_NAME = "osv.sqlite"

# No real advisory comes near this; a zip entry that claims to (or turns
# out to) is refused, not read into memory.
MAX_ADVISORY_BYTES = 5 * 1024 * 1024


def data_dir() -> Path:
    """$VULNSCAN_DATA, else $XDG_CACHE_HOME/vulnscan, else ~/.cache/vulnscan:
    outside any repository (the data is large, and it is not code)."""
    if explicit := os.environ.get("VULNSCAN_DATA"):
        return Path(explicit)
    cache = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(cache) / "vulnscan"


def read_export(path: Path) -> Iterator[Advisory | str]:
    """Each advisory in an OSV export, or a message for one that is not."""
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.endswith(".json"):
                continue
            if info.file_size > MAX_ADVISORY_BYTES:
                yield f"{info.filename}: larger than 5 MB"
                continue
            with zf.open(info) as f:
                raw = f.read(MAX_ADVISORY_BYTES + 1)
            if len(raw) > MAX_ADVISORY_BYTES:
                yield f"{info.filename}: larger than 5 MB"
                continue
            try:
                parsed = parse_advisory(json.loads(raw))
            except ValueError as error:
                yield f"{info.filename}: not JSON ({error})"
                continue
            yield (
                parsed if isinstance(parsed, Advisory) else f"{info.filename}: {parsed}"
            )


def update(
    data: Path,
    ecosystem: str,
    source: Path | None = None,
    keep: bool = False,
    url_template: str = EXPORT_URL,
) -> Snapshot:
    """Indexes one ecosystem's export: downloaded, or from ``source``."""
    db = Database(data / DB_NAME)
    try:
        if source is not None:
            got, origin = file_info(source), str(source)
        else:
            origin = url_template.format(ecosystem=ecosystem)
            (data / "download").mkdir(parents=True, exist_ok=True)
            got = download(origin, data / "download" / f"{ecosystem}.zip")
        try:
            return db.replace(
                ecosystem,
                read_export(got.path),
                Snapshot(
                    ecosystem=ecosystem,
                    source=origin,
                    bytes=got.bytes,
                    sha256=got.sha256,
                    md5_checked=got.md5_checked,
                    last_modified=got.last_modified,
                    built=datetime.now(UTC).isoformat(timespec="seconds"),
                    advisories=0,
                    withdrawn=0,
                    rejected=0,
                ),
            )
        finally:
            if source is None and not keep:
                got.path.unlink(missing_ok=True)
    finally:
        db.close()


@dataclass(frozen=True)
class Match:
    advisory: Advisory
    verdict: Verdict


def lookup(db: Database, ecosystem: str, name: str, version: str) -> list[Match]:
    """The advisories that affect this version, or may (UNKNOWN); not the
    ones that do not."""
    found: dict[str, Match] = {}
    for advisory, affected in db.lookup(ecosystem, name):
        verdict = evaluate(version, affected)
        if verdict is Verdict.NOT_AFFECTED:
            continue
        # An advisory can list one package twice: the surer answer counts.
        earlier = found.get(advisory.id)
        if earlier is None or earlier.verdict is Verdict.UNKNOWN:
            found[advisory.id] = Match(advisory, verdict)
    return list(found.values())
