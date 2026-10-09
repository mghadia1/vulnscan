"""Enough of a POSIX shell's grammar to see what a RUN line runs: its
commands, how they are joined (``|``, ``&&``, ``||``, ``;``, ``&``,
newlines), and the commands inside ``$( )``, backticks and ``<( )``.

Words are split as the shell splits them (quotes and backslashes), but
nothing is expanded: ``$URL`` stays ``$URL``. Redirections are kept as
words. This is for finding a pattern (a download piped into a shell), not
for running anything.
"""

from dataclasses import dataclass, field

_OPERATORS = ("&&", "||", ";;", "|&", "|", "&", ";", "\n", "(", ")")


@dataclass
class Command:
    words: list[str] = field(default_factory=list)
    # The text inside each substitution in this command's words.
    inner: list[str] = field(default_factory=list)


def _substitution(text: str, i: int, open_: str, close: str) -> tuple[str, int]:
    """The text inside a ``$(``/``<(`` ... ``)`` starting at ``i`` (just
    past the opening), and where it ends; nested parentheses and quotes
    are skipped over."""
    depth = 1
    quote = ""
    start = i
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "\\":
            i += 1
        elif c == open_:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1
        i += 1
    return text[start:], len(text)


def pipelines(text: str) -> list[list[Command]]:
    """The command's pipelines: each a list of commands joined by ``|``."""
    result: list[list[Command]] = []
    current: list[Command] = [Command()]
    word: list[str] = []
    in_word = False

    def end_word() -> None:
        nonlocal word, in_word
        if in_word:
            current[-1].words.append("".join(word))
        word, in_word = [], False

    def end_pipeline() -> None:
        end_word()
        commands = [c for c in current if c.words or c.inner]
        if commands:
            result.append(commands)
        current[:] = [Command()]

    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            if text[i + 1] == "\n":
                i += 2  # a line continuation
                continue
            word.append(text[i + 1])
            in_word = True
            i += 2
            continue
        if c == "'":
            end = text.find("'", i + 1)
            end = len(text) if end < 0 else end
            word.append(text[i + 1 : end])
            in_word = True
            i = end + 1
            continue
        if c == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                if text[i] == "\\" and i + 1 < len(text):
                    word.append(text[i + 1])
                    i += 2
                elif text.startswith("$(", i):
                    inner, i = _substitution(text, i + 2, "(", ")")
                    current[-1].inner.append(inner)
                    word.append("$(" + inner + ")")
                elif text[i] == "`":
                    end = text.find("`", i + 1)
                    end = len(text) if end < 0 else end
                    current[-1].inner.append(text[i + 1 : end])
                    word.append(text[i : end + 1])
                    i = end + 1
                else:
                    word.append(text[i])
                    i += 1
            in_word = True
            i += 1
            continue
        if text.startswith(("$(", "<(", ">("), i) and not text.startswith("$((", i):
            inner, j = _substitution(text, i + 2, "(", ")")
            current[-1].inner.append(inner)
            word.append(text[i:j])
            in_word = True
            i = j
            continue
        if c == "`":
            end = text.find("`", i + 1)
            end = len(text) if end < 0 else end
            current[-1].inner.append(text[i + 1 : end])
            word.append(text[i : end + 1])
            in_word = True
            i = end + 1
            continue
        if c == "#" and not in_word:
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        if c in " \t":
            end_word()
            i += 1
            continue
        op = next((o for o in _OPERATORS if text.startswith(o, i)), None)
        if op is not None:
            if op in ("|", "|&"):
                end_word()
                current.append(Command())
            else:
                end_pipeline()
            i += len(op)
            continue
        word.append(c)
        in_word = True
        i += 1
    end_pipeline()
    return result


# -- what a command is ------------------------------------------------------------

DOWNLOADERS = frozenset({"curl", "wget", "fetch", "aria2c", "http", "https"})
SHELLS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "ash",
        "ksh",
        "fish",
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "node",
        "php",
    }
)
# Run the command named after them: these do not change what it is.
_PREFIXES = frozenset({"sudo", "env", "exec", "nice", "nohup", "time", "command"})
_RUNS_TEXT = frozenset({"eval", "source", "."})


def program(command: Command) -> str | None:
    """The program a command runs (``sudo -E bash -s`` runs bash),
    without its directory."""
    words = command.words
    i = 0
    while i < len(words):
        w = words[i]
        name = w.rsplit("/", 1)[-1]
        if "=" in w and not w.startswith("-") and name == w:
            i += 1  # VAR=value before the command
            continue
        if name in _PREFIXES:
            i += 1
            while i < len(words) and words[i].startswith("-"):
                i += 1
            continue
        return name
    return None


def downloads(command: Command) -> bool:
    return program(command) in DOWNLOADERS


def runs_code(command: Command) -> bool:
    p = program(command)
    return p is not None and (p in SHELLS or p.startswith(("python3.", "python2.")))


def _script(command: Command) -> str | None:
    """The script a shell is given with ``-c``, if any."""
    if program(command) not in SHELLS:
        return None
    words = command.words
    for n, w in enumerate(words[:-1]):
        if w.startswith("-") and not w.startswith("--") and "c" in w[1:]:
            return words[n + 1]
    return None


def piped_downloads(text: str, depth: int = 0) -> list[str]:
    """Each way ``text`` runs downloaded code without checking it: a
    download piped into a shell or interpreter (``curl ... | sh``), or a
    shell, interpreter, ``eval`` or ``source`` given a download's output
    (``bash <(curl ...)``, ``sh -c "$(wget -O- ...)"``). Scripts given to
    ``sh -c`` and the insides of substitutions are read the same way."""
    if depth > 10:
        return []
    found: list[str] = []
    for pipeline in pipelines(text):
        for n, command in enumerate(pipeline):
            if downloads(command):
                later = [c for c in pipeline[n + 1 :] if runs_code(c)]
                if later:
                    found.append(f"{program(command)} piped into {program(later[0])}")
            if runs_code(command) or program(command) in _RUNS_TEXT:
                inner = [
                    c for text in command.inner for p in pipelines(text) for c in p
                ]
                download = next((c for c in inner if downloads(c)), None)
                if download is not None:
                    found.append(
                        f"{program(command)} given {program(download)}'s output"
                    )
            for inner_text in command.inner:
                found += piped_downloads(inner_text, depth + 1)
            script = _script(command)
            if script is not None:
                found += piped_downloads(script, depth + 1)
    return found
