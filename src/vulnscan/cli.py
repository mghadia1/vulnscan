"""The command line.

- ``vulnscan scan PATH``: the scan: dependencies against advisories, and
  secrets in files and git history. Reads files only; never the network.
- ``vulnscan update``: downloads OSV's advisory exports and indexes them
  (the only command that uses the network).
- ``vulnscan lookup ECOSYSTEM NAME VERSION``: which advisories affect one
  package version, from the local index.

Exit codes, as linters use them: 0, nothing to report at or above the
failure threshold; 1, findings at or above it (for lookup: affected); 2, the
command could not be done (a bad path or option, no advisory data).
"""

import argparse
import sys
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path

from vulnscan import __version__, secrets
from vulnscan.advisories import (
    DB_NAME,
    ECOSYSTEMS,
    Database,
    data_dir,
    lookup,
    update,
)
from vulnscan.advisories.fetch import FetchError
from vulnscan.advisories.osv import Verdict
from vulnscan.baseline import FILE_NAME, BaselineError, apply, load
from vulnscan.findings import Acceptance
from vulnscan.findings import match as match_advisories
from vulnscan.report import THRESHOLDS, Checked, Report, SecretsChecked
from vulnscan.walk import walk

# Advisories older than this are named in the report (not a failure).
STALE_AFTER = timedelta(days=7)

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description=(
            "A defensive scanner for repositories you own: it reads files and "
            "never changes them; only `update` uses the network."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan a directory")
    scan.add_argument("path", type=Path, help="the repository (a directory)")
    scan.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="text for people (default), json for tools, sarif for code scanning",
    )
    scan.add_argument(
        "--fail-on",
        choices=THRESHOLDS,
        default="low",
        help="exit 1 for a finding at or above this severity (default: low)",
    )
    scan.add_argument(
        "--baseline",
        type=Path,
        help=f"accepted findings (default: {FILE_NAME} in the target, if there)",
    )
    scan.add_argument(
        "--no-baseline", action="store_true", help="ignore any accepted findings"
    )
    scan.add_argument(
        "--no-advisories",
        action="store_true",
        help="list the inventory only, without checking it",
    )
    scan.add_argument(
        "--no-secrets", action="store_true", help="do not look for secrets"
    )
    scan.add_argument(
        "--no-history",
        action="store_true",
        help="look for secrets in the commit checked out only, not all history",
    )
    scan.add_argument(
        "--output",
        type=Path,
        help="write the report to this file instead of standard output",
    )

    data_help = (
        "where advisory data is kept (default: $VULNSCAN_DATA or ~/.cache/vulnscan)"
    )
    scan.add_argument("--data", type=Path, help=data_help)
    upd = commands.add_parser("update", help="download and index OSV's advisories")
    upd.add_argument(
        "--ecosystem",
        action="append",
        choices=ECOSYSTEMS,
        help="only this ecosystem (repeatable; default: all of them)",
    )
    upd.add_argument(
        "--from",
        dest="sources",
        action="append",
        default=[],
        metavar="ECOSYSTEM=ZIP",
        help="index an export already on disk instead of downloading it",
    )
    upd.add_argument("--keep", action="store_true", help="keep the downloaded zips")
    upd.add_argument("--data", type=Path, help=data_help)

    look = commands.add_parser("lookup", help="advisories for one package version")
    look.add_argument("ecosystem", choices=ECOSYSTEMS)
    look.add_argument("name")
    look.add_argument("version")
    look.add_argument("--data", type=Path, help=data_help)
    return parser


def _scan(args: argparse.Namespace) -> int:
    target: Path = args.path
    if not target.exists():
        print(f"vulnscan: no such directory: {target}", file=sys.stderr)
        return EXIT_ERROR
    if not target.is_dir():
        print(f"vulnscan: not a directory: {target}", file=sys.stderr)
        return EXIT_ERROR
    root = target.resolve()
    report = Report.from_tree(str(target), walk(root))
    report = replace(report, threshold=args.fail_on)
    baseline: Path | None = None
    if not args.no_baseline:
        baseline = args.baseline
        if baseline is None and (target / FILE_NAME).is_file():
            baseline = target / FILE_NAME
    try:
        acceptances = load(baseline) if baseline is not None else []
    except BaselineError as error:
        print(f"vulnscan: {error}", file=sys.stderr)
        return EXIT_ERROR
    if not args.no_advisories:
        checked = _check(args, report, acceptances, baseline)
        if isinstance(checked, int):
            return checked
        report = replace(report, checked=checked)
    if not args.no_secrets:
        found = secrets.scan(root, report.tree, history=not args.no_history)
        applied = secrets.apply(found.findings, acceptances, date.today())
        report = replace(
            report,
            secrets=SecretsChecked(found, applied, str(baseline) if baseline else None),
        )
    if args.format == "json":
        text = report.to_json()
    elif args.format == "sarif":
        text = report.to_sarif()
    else:
        text = report.to_text()
    if args.output is None:
        sys.stdout.write(text)
    else:
        args.output.write_text(text, encoding="utf-8")
    if report.unchecked:
        # Not everything could be checked: never a clean result.
        print(
            "vulnscan: not checked, no advisory data: "
            + ", ".join(f"{n} {e} packages" for e, n in report.unchecked.items()),
            file=sys.stderr,
        )
        return EXIT_ERROR
    return EXIT_FINDINGS if report.failed else EXIT_CLEAN


def _check(
    args: argparse.Namespace,
    report: Report,
    acceptances: list[Acceptance],
    baseline: Path | None,
) -> Checked | int:
    """Matches the inventory against the advisories and applies the
    baseline; an exit code if that cannot be done."""
    path = (args.data or data_dir()) / DB_NAME
    if not path.exists():
        print(
            f"vulnscan: no advisory data at {path}; run `vulnscan update` "
            "(or --no-advisories for the inventory alone)",
            file=sys.stderr,
        )
        return EXIT_ERROR
    db = Database(path, readonly=True)
    try:
        snapshots = tuple(db.snapshots())
        matching = match_advisories(report.inventory, db)
    finally:
        db.close()
    applied = apply(matching.findings, acceptances, date.today())
    notes = []
    now = datetime.now(UTC)
    for snapshot in snapshots:
        when = _as_datetime(snapshot.last_modified) or _as_datetime(snapshot.built)
        if when is not None and now - when > STALE_AFTER:
            notes.append(
                f"{snapshot.ecosystem} advisories are {(now - when).days} days old: "
                "run `vulnscan update`"
            )
    return Checked(
        snapshots=snapshots,
        matching=matching,
        applied=applied,
        baseline=str(baseline) if baseline else None,
        notes=tuple(notes),
    )


def _as_datetime(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(text)  # an HTTP date, as servers send it
    except TypeError, ValueError:
        return None


def _update(args: argparse.Namespace) -> int:
    data: Path = args.data or data_dir()
    sources: dict[str, Path] = {}
    for item in args.sources:
        ecosystem, _, path = item.partition("=")
        if ecosystem not in ECOSYSTEMS or not path:
            print(
                f"vulnscan: --from wants ECOSYSTEM=ZIP, not {item!r}", file=sys.stderr
            )
            return EXIT_ERROR
        sources[ecosystem] = Path(path)
    ecosystems = args.ecosystem or (list(sources) if sources else list(ECOSYSTEMS))
    for ecosystem in ecosystems:
        try:
            snap = update(data, ecosystem, sources.get(ecosystem), args.keep)
        except (FetchError, OSError, ValueError) as error:
            print(f"vulnscan: {ecosystem}: {error}", file=sys.stderr)
            return EXIT_ERROR
        checked = (
            "MD5 checked" if snap.md5_checked else "not checked against the server"
        )
        print(
            f"{ecosystem}: {snap.advisories:,} advisories "
            f"({snap.withdrawn:,} withdrawn left out, {snap.rejected:,} not readable); "
            f"{snap.bytes / 1e6:.1f} MB, sha256 {snap.sha256[:16]}..., {checked}"
        )
    print(f"index: {data / DB_NAME}")
    return EXIT_CLEAN


def _lookup(args: argparse.Namespace) -> int:
    path = (args.data or data_dir()) / DB_NAME
    if not path.exists():
        print(
            f"vulnscan: no advisory data at {path}; run `vulnscan update`",
            file=sys.stderr,
        )
        return EXIT_ERROR
    db = Database(path, readonly=True)
    try:
        snapshot = next(
            (s for s in db.snapshots() if s.ecosystem == args.ecosystem), None
        )
        if snapshot is None:
            print(
                f"vulnscan: no {args.ecosystem} advisories; "
                f"run `vulnscan update --ecosystem {args.ecosystem}`",
                file=sys.stderr,
            )
            return EXIT_ERROR
        matches = lookup(db, args.ecosystem, args.name, args.version)
    finally:
        db.close()
    print(
        f"{args.ecosystem} {args.name} {args.version}: "
        f"advisories as of {snapshot.last_modified or snapshot.built}"
    )
    for match in sorted(matches, key=lambda m: (m.verdict, m.advisory.id)):
        aliases = (
            f" ({', '.join(match.advisory.aliases[:3])})"
            if match.advisory.aliases
            else ""
        )
        print(
            f"  {match.verdict.upper():<9} {match.advisory.id}{aliases}: "
            f"{match.advisory.summary}"
        )
    affected = sum(m.verdict is Verdict.AFFECTED for m in matches)
    unknown = len(matches) - affected
    print(
        f"{affected} affecting it"
        + (f", {unknown} that could not be decided" if unknown else "")
    )
    return EXIT_FINDINGS if affected else EXIT_CLEAN


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "update":
        return _update(args)
    return _lookup(args)
