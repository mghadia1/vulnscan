"""Shows the lines around each secret finding, to label it by hand as a
real secret, a test or development value, or not a secret, without seeing
the value: the finding itself, and any other run of 12 or more token
characters on those lines, is masked.

    vulnscan scan PATH --format json --output scan.json
    python scripts/show_context.py PATH scan.json

A committed or uncommitted finding is read from the working tree; one only
in history, from its first commit (with VulnScan's own git reader).
"""

import json
import re
import sys
from pathlib import Path

from vulnscan.git import Repository, parse_commit, parse_tree
from vulnscan.secrets.rules import find

_RUN = re.compile(r"[A-Za-z0-9+/=_.~-]{12,}")


def _masked(line: str, spans: list[tuple[int, int]]) -> str:
    out = list(line)
    for start, end in spans:
        for i in range(max(start, 0), min(end, len(line))):
            out[i] = "•"
    text = "".join(out)
    return _RUN.sub(lambda m: f"«{len(m.group())} chars»", text)


def _blob_at(git_dir: Path, commit: str, path: str) -> bytes | None:
    repo = Repository.open(git_dir)
    try:
        _, data = repo.read(commit)
        tree = parse_commit(commit, data).tree
        for part in path.split("/"):
            entries = {name: sha for _, name, sha in parse_tree(repo.read(tree)[1])}
            if part not in entries:
                return None
            tree = entries[part]
        return repo.read(tree)[1]
    finally:
        repo.close()


def main() -> None:
    target, report = Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text())
    for f in report["secrets"]["findings"]:
        if f["state"] == "history":
            repo = f["repository"]
            inner = f["path"] if repo == "." else f["path"][len(repo) + 1 :]
            data = _blob_at(target / repo / ".git", f["commit"], inner)
        else:
            data = (target / f["path"]).read_bytes()
        if data is None:
            print(f"{f['path']}: not found")
            continue
        text = data.decode("utf-8", errors="replace")
        hits = [h for h in find(text, f["path"]) if h.rule == f["rule"]]
        lines = text.splitlines(keepends=True)
        starts = [0]
        for line in lines:
            starts.append(starts[-1] + len(line))
        n = f["line"] - 1
        where = f"{f['path']}:{f['line']} [{f['state']}]"
        print(f"== {f['severity']} {f['rule']} {where} {f['shown']}")
        for i in range(max(0, n - 3), min(len(lines), n + 4)):
            spans = [(h.start - starts[i], h.end - starts[i]) for h in hits]
            mark = ">" if i == n else " "
            print(f"  {mark}{i + 1:5} {_masked(lines[i].rstrip(), spans)}")


if __name__ == "__main__":
    main()
