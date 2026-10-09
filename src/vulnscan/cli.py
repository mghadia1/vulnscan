"""The command line: ``vulnscan scan PATH``.

Exit codes, as linters use them: 0, nothing to report at or above the
failure threshold; 1, findings at or above it; 2, the scan could not be
done (a bad path, a bad option).
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from vulnscan import __version__
from vulnscan.report import Report
from vulnscan.walk import walk

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description=(
            "A defensive scanner for repositories you own: it reads files, "
            "never changes them, and sends nothing anywhere."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a directory")
    scan.add_argument("path", type=Path, help="the repository (a directory)")
    scan.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text for people (default), json for tools",
    )
    scan.add_argument(
        "--output",
        type=Path,
        help="write the report to this file instead of standard output",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    target: Path = args.path
    if not target.exists():
        print(f"vulnscan: no such directory: {target}", file=sys.stderr)
        return EXIT_ERROR
    if not target.is_dir():
        print(f"vulnscan: not a directory: {target}", file=sys.stderr)
        return EXIT_ERROR

    report = Report.from_tree(str(target), walk(target.resolve()))
    text = report.to_json() if args.format == "json" else report.to_text()
    if args.output is None:
        sys.stdout.write(text)
    else:
        args.output.write_text(text, encoding="utf-8")
    return EXIT_FINDINGS if report.findings else EXIT_CLEAN
