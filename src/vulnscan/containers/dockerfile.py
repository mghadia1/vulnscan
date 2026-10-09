"""A Dockerfile, read by hand the way BuildKit (Docker's builder) reads it.

- **Parser directives** at the very top (``# syntax=``, ``# escape=``): the
  escape directive changes the line-continuation character (``\\`` or a
  backtick).
- **Lines:** an instruction's first line has its leading whitespace
  removed; a line ending in the escape character (and spaces or tabs)
  continues on the next, which is appended as it is; comment lines and
  empty lines inside a continued instruction are skipped. Comments are
  whole lines only: a ``#`` after an instruction is part of it.
- **Instructions:** the keyword (any case), flags (``--from=build``), and
  the rest. RUN, CMD, ENTRYPOINT and SHELL are in exec form when the rest
  is exactly a JSON array of strings, otherwise shell form; HEALTHCHECK's
  CMD likewise; COPY, ADD and VOLUME may list their paths that way too.
- **Heredocs** (``RUN <<EOF`` ... ``EOF``, also ``<<-`` and quoted names)
  on RUN, COPY and ADD: their lines belong to the instruction.

Checked against BuildKit's own parser (``scripts/check_dockerfile_parser.py``):
the same instructions, lines, text, flags, forms and heredocs.
"""

import json
import re
from dataclasses import dataclass, field

_DIRECTIVE = re.compile(r"^#\s*([a-zA-Z][a-zA-Z0-9]*)\s*=\s*(.+?)\s*$")
_HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
_HEREDOC_INSTRUCTIONS = frozenset({"RUN", "COPY", "ADD"})
# Instructions that take a JSON array: a command (exec form) or a list of
# paths.
_JSON_INSTRUCTIONS = frozenset(
    {"RUN", "CMD", "ENTRYPOINT", "SHELL", "COPY", "ADD", "VOLUME"}
)
_FLAG = re.compile(r"--([A-Za-z][A-Za-z0-9-]*)(?:=(\S*))?")


class DockerfileError(Exception):
    def __init__(self, message: str, line: int) -> None:
        super().__init__(f"line {line}: {message}")
        self.line = line


@dataclass(frozen=True)
class Instruction:
    keyword: str  # upper case
    original: str  # the instruction's lines joined, as BuildKit joins them
    line: int
    end_line: int
    flags: tuple[str, ...]  # as written: "--from=build"
    rest: str  # after the keyword and flags
    exec_form: tuple[str, ...] | None  # the JSON array, if written as one
    heredocs: tuple[tuple[str, str], ...] = ()  # (name, content)

    def flag(self, name: str) -> str | None:
        """A flag's value ("" for a flag with none), or None if absent."""
        for f in self.flags:
            m = _FLAG.fullmatch(f)
            if m and m.group(1).lower() == name:
                return m.group(2) or ""
        return None


@dataclass(frozen=True)
class Dockerfile:
    instructions: tuple[Instruction, ...]
    escape: str
    directives: dict[str, str] = field(default_factory=dict)


def _leading_flags(text: str) -> tuple[tuple[str, ...], str]:
    """Flags at the start of an instruction's arguments, as BuildKit takes
    them (``--name`` or ``--name=value``, the value perhaps quoted)."""
    flags: list[str] = []
    rest = text.lstrip()
    while rest.startswith("--"):
        i = 2
        quote = ""
        while i < len(rest):
            c = rest[i]
            if quote:
                if c == quote:
                    quote = ""
            elif c in "\"'":
                quote = c
            elif c.isspace():
                break
            i += 1
        flag = rest[:i]
        if flag == "--":
            break
        flags.append(flag)
        rest = rest[i:].lstrip()
    return tuple(flags), rest


def _json_array(rest: str) -> tuple[str, ...] | None:
    if not rest.startswith("["):
        return None
    try:
        value = json.loads(rest)
    except ValueError:
        return None
    if not isinstance(value, list):
        return None
    if not all(isinstance(v, str) for v in value):
        return None
    return tuple(value)


def parse(text: str) -> Dockerfile:
    raw = text.removeprefix("\ufeff").split("\n")
    if raw and raw[-1] == "" and text.endswith("\n"):
        raw.pop()
    # Instructions are read without line-end characters; heredoc bodies
    # keep a CR, as BuildKit keeps it.
    lines = [line.rstrip("\r") for line in raw]
    escape = "\\"
    directives: dict[str, str] = {}
    # Directives: only at the very top, before anything else.
    n = 0
    while n < len(lines):
        m = _DIRECTIVE.match(lines[n].strip())
        if not m or m.group(1).lower() in directives:
            break
        directives[m.group(1).lower()] = m.group(2)
        n += 1
    if "escape" in directives:
        if directives["escape"] not in ("\\", "`"):
            raise DockerfileError("escape must be \\ or `", 1)
        escape = directives["escape"]
    continuation = re.compile(re.escape(escape) + r"[ \t]*$")

    def is_comment(line: str) -> bool:
        return line.lstrip().startswith("#")

    def trim(line: str) -> tuple[str, bool]:
        """The line without its continuation character, and whether the
        instruction ends here."""
        if continuation.search(line):
            return continuation.sub("", line), False
        return line, True

    instructions: list[Instruction] = []
    i = 0
    while i < len(lines):
        first = lines[i]
        i += 1
        start = i
        if is_comment(first):
            continue
        line, ended = trim(first.lstrip())
        if ended and not line.strip():
            continue
        while not ended and i < len(lines):
            nxt = lines[i]
            i += 1
            if is_comment(nxt):
                continue
            if not nxt.strip():
                continue  # an empty line inside a continued instruction
            part, ended = trim(nxt)
            line += part
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        keyword = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""
        flags, rest = _leading_flags(args)
        rest = rest.strip()
        exec_form = None
        if keyword in _JSON_INSTRUCTIONS:
            exec_form = _json_array(rest)
        elif keyword == "HEALTHCHECK":
            # After its type (CMD, or NONE, which BuildKit refuses later).
            cmd = rest.split(None, 1)
            if len(cmd) == 2:
                exec_form = _json_array(cmd[1].strip())
        heredocs: list[tuple[str, str]] = []
        if keyword in _HEREDOC_INSTRUCTIONS and "<<" in line and exec_form is None:
            for m in _HEREDOC.finditer(rest):
                chomp, name = m.group(1) == "-", m.group(3)
                body: list[str] = []
                while True:
                    if i >= len(lines):
                        raise DockerfileError(f"heredoc {name} never ends", start)
                    candidate = lines[i]
                    i += 1
                    if (candidate.lstrip("\t") if chomp else candidate) == name:
                        break
                    body.append(raw[i - 1] + "\n")
                heredocs.append((name, "".join(body)))
        instructions.append(
            Instruction(
                keyword=keyword,
                original=line,  # leading whitespace gone, trailing kept
                line=start,
                end_line=i,
                flags=flags,
                rest=rest,
                exec_form=exec_form,
                heredocs=tuple(heredocs),
            )
        )
    return Dockerfile(tuple(instructions), escape, directives)


# -- words ---------------------------------------------------------------------


def words(text: str, escape: str = "\\") -> list[str]:
    """Shell-like words, as BuildKit splits ENV, ARG, USER and the like:
    whitespace separates; quotes group (and are removed); the escape
    character takes the next character literally (inside double quotes,
    only before a quote, the escape character itself or $)."""
    out: list[str] = []
    word: list[str] = []
    in_word = False
    i = 0
    while i < len(text):
        c = text[i]
        if c.isspace():
            if in_word:
                out.append("".join(word))
                word, in_word = [], False
            i += 1
            continue
        in_word = True
        if c == escape and i + 1 < len(text):
            word.append(text[i + 1])
            i += 2
        elif c == "'":
            end = text.find("'", i + 1)
            if end < 0:
                end = len(text)
            word.append(text[i + 1 : end])
            i = end + 1
        elif c == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                if (
                    text[i] == escape
                    and i + 1 < len(text)
                    and text[i + 1]
                    in (
                        '"',
                        escape,
                        "$",
                    )
                ):
                    word.append(text[i + 1])
                    i += 2
                else:
                    word.append(text[i])
                    i += 1
            i += 1
        else:
            word.append(c)
            i += 1
    if in_word:
        out.append("".join(word))
    return out


def assignments(rest: str, escape: str = "\\") -> list[tuple[str, str | None]]:
    """ENV or ARG pairs: ``a=1 b="two words"``, the old ``ENV name value``
    form, and ARG's ``name`` with no default (value None)."""
    items = words(rest, escape)
    if items and "=" not in items[0]:
        if len(items) == 1:
            return [(items[0], None)]
        # The old form: ENV name value (the rest of the line is the value).
        name, _, value = rest.strip().partition(" ")
        return [(name, " ".join(words(value, escape)))]
    pairs: list[tuple[str, str | None]] = []
    for item in items:
        name, sep, value = item.partition("=")
        pairs.append((name, value if sep else None))
    return pairs
