"""How long a scan takes, by part, on a real tree (macOS: it reads vm_stat
and /usr/bin/time -l).

    python bench/scan_time.py ROOT [--reps 5]

Five configurations: the whole scan, and each part alone (dependencies,
secrets with all history, secrets in HEAD only, containers). One warm-up
scan first (discarded): every number here is a warm one, with the files in
the operating system's cache; a cold first scan is not measured (that needs
the cache emptied, which needs sudo). Configurations are interleaved, one
of each per pass, so drift on the machine falls on all of them alike.

Each run records its wall time, CPU time (user + system), peak memory, and
how much the host swapped in while it ran; a run with more than 50 MB
swapped in is invalid and left out of the summary (kept in the results).
Results go to bench/results/<time>.json.
"""

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
SWAP_TOLERANCE_MB = 50.0
CONFIGS: dict[str, list[str]] = {
    "whole scan": [],
    "dependencies": ["--no-secrets", "--no-containers"],
    "secrets (all history)": ["--no-advisories", "--no-containers"],
    "secrets (HEAD only)": ["--no-advisories", "--no-containers", "--no-history"],
    "containers": ["--no-advisories", "--no-secrets"],
}


def swapped_in_mb() -> float:
    out = subprocess.run(["vm_stat"], capture_output=True, text=True, check=True).stdout
    page = int(out.split("page size of ")[1].split(" bytes")[0])
    for line in out.splitlines():
        name, _, value = line.partition(":")
        if name == "Swapins":
            return int(value.strip().rstrip(".")) * page / 2**20
    raise RuntimeError("no Swapins in vm_stat")


def busy(threshold: float = 20.0) -> list[str]:
    out = subprocess.run(
        ["ps", "-Ao", "%cpu=,comm="], capture_output=True, text=True
    ).stdout
    found = []
    for line in out.splitlines():
        cpu, _, command = line.strip().partition(" ")
        if cpu and float(cpu) >= threshold:
            found.append(f"{float(cpu):.0f}% {command.strip().rsplit('/', 1)[-1]}")
    return found


def run(root: Path, extra: list[str]) -> dict[str, object]:
    command = [
        "/usr/bin/time",
        "-l",
        sys.executable,
        "-m",
        "vulnscan",
        "scan",
        str(root),
        "--format",
        "json",
        "--output",
        os.devnull,
        *extra,
    ]
    env = {**os.environ, "PYTHONPATH": str(PROJECT / "src")}
    before = swapped_in_mb()
    start = time.perf_counter()
    done = subprocess.run(command, env=env, capture_output=True, text=True)
    wall = time.perf_counter() - start
    swapped = swapped_in_mb() - before
    stats: dict[str, float] = {}
    for line in done.stderr.splitlines():
        # "2.25 real  1.80 user  0.35 sys" on one line: numbers, then names.
        parts = line.split()
        for value, label in zip(parts, parts[1:], strict=False):
            if label in ("user", "sys"):
                stats[label] = float(value)
        if line.strip().endswith("maximum resident set size"):
            stats["rss_mb"] = int(line.split()[0]) / 2**20
    return {
        "exit": done.returncode,
        "wall_s": round(wall, 3),
        "cpu_s": round(stats.get("user", 0) + stats.get("sys", 0), 3),
        "rss_mb": round(stats.get("rss_mb", 0), 1),
        "swapped_in_mb": round(swapped, 1),
        "valid": swapped <= SWAP_TOLERANCE_MB and done.returncode in (0, 1),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--reps", type=int, default=5)
    args = parser.parse_args()
    root = args.root.resolve()
    results: dict[str, object] = {
        "started": datetime.now(UTC).isoformat(timespec="seconds"),
        "machine": f"{platform.machine()} {platform.mac_ver()[0]}",
        "python": platform.python_version(),
        "root": str(root),
        "busy_at_start": busy(),
        "swap_at_start": subprocess.run(
            ["sysctl", "-n", "vm.swapusage"], capture_output=True, text=True
        ).stdout.strip(),
        "warm_up": run(root, []),
        "runs": [],
    }
    runs: list[dict[str, object]] = []
    for rep in range(args.reps):
        for name, extra in CONFIGS.items():
            record = {"config": name, "pass": rep + 1, **run(root, extra)}
            runs.append(record)
            flag = "" if record["valid"] else "  INVALID"
            print(
                f"pass {rep + 1} {name:24} {record['wall_s']:7.2f} s wall "
                f"{record['cpu_s']:6.2f} s cpu {record['rss_mb']:6.1f} MB "
                f"swap-in {record['swapped_in_mb']} MB{flag}",
                flush=True,
            )
    results["runs"] = runs
    summary = {}
    for name in CONFIGS:
        valid = [r for r in runs if r["config"] == name and r["valid"]]
        walls = [float(r["wall_s"]) for r in valid]  # type: ignore[arg-type]
        cpus = [float(r["cpu_s"]) for r in valid]  # type: ignore[arg-type]
        summary[name] = {
            "valid_runs": len(valid),
            "of": args.reps,
            "wall_median_s": round(statistics.median(walls), 2) if walls else None,
            "wall_min_s": min(walls) if walls else None,
            "wall_max_s": max(walls) if walls else None,
            "cpu_median_s": round(statistics.median(cpus), 2) if cpus else None,
            "rss_max_mb": max((float(r["rss_mb"]) for r in valid), default=None),  # type: ignore[arg-type]
        }
    results["summary"] = summary
    out = HERE / "results" / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + ".json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=1) + "\n")
    print(json.dumps(summary, indent=1))
    print(f"results: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
