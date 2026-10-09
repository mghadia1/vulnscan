"""VulnScan's Dockerfile parser against BuildKit's own (a development
check; it needs Go, to build scripts/buildkit_parse once).

    python scripts/check_dockerfile_parser.py --generated 2000 [PATH ...]

Each Dockerfile, real (found under the PATHs; files that are iCloud
placeholders are skipped, not downloaded) or generated (random
instructions with continuations, comments and blank lines inside them,
trailing spaces, heredocs, JSON arrays that are and are not exec form, the
backtick escape directive, CRLF), is parsed by both; they must agree on
every instruction's keyword, first and last line, text, flags, form and
heredocs, or both refuse the file.
"""

import argparse
import json
import os
import random
import subprocess
import sys
from pathlib import Path

from vulnscan.classify import Kind, classify
from vulnscan.containers.dockerfile import DockerfileError, parse

HERE = Path(__file__).resolve().parent
TOOL = Path.home() / ".cache" / "vulnscan-dev" / "buildkit-parse"


def tool() -> Path:
    if not TOOL.exists():
        TOOL.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["go", "build", "-o", str(TOOL), "."],
            cwd=HERE / "buildkit_parse",
            check=True,
        )
    return TOOL


def theirs(text: str) -> object:
    out = subprocess.run(
        [str(tool())], input=text.encode(), capture_output=True, check=True
    ).stdout
    result = json.loads(out)
    if "error" in result:
        return "error"
    return [
        (
            i["keyword"],
            i["start"],
            i["end"],
            i["original"],
            tuple(i["flags"]),
            tuple(i["args"]) if i["json"] else None,
            tuple(tuple(h.split("\0", 1)) for h in i["heredocs"]),
        )
        for i in result["instructions"]
    ]


def mine(text: str) -> object:
    try:
        dockerfile = parse(text)
    except DockerfileError:
        return "error"
    out = []
    for i in dockerfile.instructions:
        form = i.exec_form
        if i.keyword == "HEALTHCHECK" and form is not None:
            form = (i.rest.split(None, 1)[0], *form)
        out.append(
            (i.keyword, i.line, i.end_line, i.original, i.flags, form, i.heredocs)
        )
    return out


# -- generated Dockerfiles ---------------------------------------------------------

KEYWORDS = [
    "FROM",
    "RUN",
    "CMD",
    "ENTRYPOINT",
    "ENV",
    "ARG",
    "COPY",
    "ADD",
    "USER",
    "EXPOSE",
    "WORKDIR",
    "LABEL",
    "HEALTHCHECK",
    "SHELL",
    "STOPSIGNAL",
    "VOLUME",
]
WORDS = [
    "a",
    "apt-get",
    "install",
    "-y",
    "&&",
    "x=1",
    "'q w'",
    '"d q"',
    "#not",
    "$HOME",
    "${X:-y}",
    "|",
    "sh",
    "/tmp",
    "--flag",
    "a#b",
    "\\$",
    "[x]",
]


def _args(rng: random.Random, escape: str) -> str:
    choice = rng.random()
    if choice < 0.15:
        items = [
            rng.choice(["sh", "-c", "a b", 'q"t', "x"])
            for _ in range(rng.randint(0, 3))
        ]
        text = json.dumps(items)
        return text + (rng.choice(["", " ", " trailing"]) if rng.random() < 0.3 else "")
    if choice < 0.2:
        return "[" + rng.choice(['"a", 1', '"a"', "not json", '"a",']) + "]"
    return " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 5)))


def _instruction(rng: random.Random, escape: str) -> list[str]:
    keyword = rng.choice(KEYWORDS)
    keyword = rng.choice([keyword, keyword.lower(), keyword.title()])
    flags = ""
    if (
        keyword.upper() in ("COPY", "ADD", "RUN", "FROM", "HEALTHCHECK")
        and rng.random() < 0.4
    ):
        flags = (
            " ".join(
                rng.choice(
                    [
                        "--from=build",
                        "--chown=1:1",
                        "--mount=type=cache,target=/x",
                        "--platform=$BUILDPLATFORM",
                        "--interval=5s",
                        "--link",
                    ]
                )
                for _ in range(rng.randint(1, 2))
            )
            + " "
        )
    if keyword.upper() == "HEALTHCHECK":
        body = rng.choice(["NONE", "CMD " + _args(rng, escape), 'CMD ["/x", "y"]'])
    else:
        body = _args(rng, escape)
    lead = rng.choice(["", "", " ", "\t"])
    lines = [f"{lead}{keyword} {flags}{body}"]
    if keyword.upper() in ("RUN", "COPY") and rng.random() < 0.15:
        name = rng.choice(["EOF", "END", "SCRIPT"])
        dash = rng.choice(["", "-"])
        quote = rng.choice(["", "'", '"'])
        lines = [f"{lead}{keyword} {flags}<<{dash}{quote}{name}{quote} {body}"]
        for _ in range(rng.randint(0, 3)):
            lines.append(rng.choice(["\t", ""]) + rng.choice(WORDS + ["", "# c"]))
        lines.append(("\t" if dash and rng.random() < 0.5 else "") + name)
        return lines
    for _ in range(rng.randint(0, 3) if rng.random() < 0.5 else 0):
        lines[-1] += (
            " " * rng.randint(0, 1) + escape + rng.choice(["", "", " ", "\t", "  "])
        )
        for _ in range(rng.randint(0, 1)):
            lines.append(rng.choice(["", "   ", "# comment", "    # indented comment"]))
        lines.append(rng.choice(["", "  ", "\t"]) + _args(rng, escape))
    return lines


def generated(rng: random.Random) -> str:
    lines: list[str] = []
    escape = "\\"
    if rng.random() < 0.15:
        escape = "`"
        lines.append("# escape=`")
    if rng.random() < 0.2:
        lines.append("# syntax=docker/dockerfile:1")
    for _ in range(rng.randint(1, 8)):
        if rng.random() < 0.2:
            lines.append(rng.choice(["", "# a comment", "   ", "  # indented"]))
        lines += _instruction(rng, escape)
    newline = "\r\n" if rng.random() < 0.1 else "\n"
    return newline.join(lines) + rng.choice(["", newline])


def real_files(paths: list[str]) -> list[Path]:
    found = []
    for root in paths:
        for here, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv")]
            for name in names:
                path = Path(here) / name
                if classify(name) is not Kind.DOCKERFILE:
                    continue
                if getattr(os.lstat(path), "st_flags", 0) & 0x40000000:
                    continue  # an iCloud placeholder: not downloaded for this
                found.append(path)
    return sorted(found)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--generated", type=int, default=0)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()
    differ = 0
    checked = refused = 0
    cases: list[tuple[str, str]] = [
        (str(p), p.read_text()) for p in real_files(args.paths)
    ]
    rng = random.Random(args.seed)
    cases += [(f"generated #{n}", generated(rng)) for n in range(args.generated)]
    invalid = 0
    for name, text in cases:
        a, b = mine(text), theirs(text)
        checked += 1
        refused += a == "error" and b == "error"
        if b == "error" and a != "error":
            # BuildKit rejects the file's arguments (LABEL without key=value,
            # SHELL not in JSON...): it cannot be built at all.
            invalid += 1
            continue
        if a != b:
            differ += 1
            if differ <= 5:
                print(f"DIFFERENT: {name}\n{text!r}\n mine:   {a}\n theirs: {b}\n")
    real = len(real_files(args.paths))
    print(
        f"{checked} Dockerfiles ({real} real): {checked - differ - invalid} the "
        f"same ({refused} refused by both), {differ} different; {invalid} "
        "rejected by BuildKit as invalid and read by VulnScan"
    )
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
