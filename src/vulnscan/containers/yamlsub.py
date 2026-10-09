"""The part of YAML that Compose files use, read by hand.

Supported: block mappings and sequences (a sequence may sit at its key's
indentation), plain, single- and double-quoted scalars, flow sequences
and mappings (over several lines too), literal and folded block scalars
(``|``, ``>``, with ``-`` or ``+``), comments, anchors, aliases and merge
keys (``<<: *defaults``, ``<<: [*a, *b]``: keys written in the mapping
win, then earlier sources over later ones), and a leading ``---``.

Every scalar is kept as text, exactly as written (after quotes and escapes
are removed): "8080", "true" and "~" stay strings, and an empty value is
"". That is what the rules need (they read ports, images and settings as
written), and it is what PyYAML's loader gives when every scalar is read as
a string, which is what the tests compare against.

Anything else is refused with a ``YamlError`` naming the line, never
guessed: tags (``!reset``), several documents, ``?`` keys, multi-line
quoted scalars, block scalars with an explicit indentation, duplicate keys,
and tabs used for indentation. A file that is refused is reported as not
read.
"""

import re
from dataclasses import dataclass

_MAX_DEPTH = 64
_MAX_ALIASES = 10_000


class YamlError(Exception):
    def __init__(self, message: str, line: int) -> None:
        super().__init__(f"line {line}: {message}")
        self.line = line


@dataclass
class Node:
    """A value and the line it starts on (1-based)."""

    value: dict[str, Node] | list[Node] | str
    line: int

    def get(self, key: str) -> Node | None:
        return self.value.get(key) if isinstance(self.value, dict) else None

    @property
    def text(self) -> str | None:
        return self.value if isinstance(self.value, str) else None


def plain(node: Node | None) -> object:
    """The value as dicts, lists and strings (for tests and debugging)."""
    if node is None:
        return None
    if isinstance(node.value, dict):
        return {k: plain(v) for k, v in node.value.items()}
    if isinstance(node.value, list):
        return [plain(v) for v in node.value]
    return node.value


_ANCHOR = re.compile(r"[&*]([^\s,\[\]{}]+)")
_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "\t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": " ",
    "P": " ",
}
_HEX_ESCAPES = {"x": 2, "u": 4, "U": 8}


def _comment_start(text: str) -> int:
    """Where a comment starts in a line's content (len(text) if none): a
    "#" at the start or after whitespace, outside quotes."""
    quote = ""
    i = 0
    while i < len(text):
        c = text[i]
        if quote == '"':
            if c == "\\":
                i += 1
            elif c == '"':
                quote = ""
        elif quote == "'":
            if c == "'":
                if i + 1 < len(text) and text[i + 1] == "'":
                    i += 1
                else:
                    quote = ""
        elif c == "#" and (i == 0 or text[i - 1] in " \t"):
            return i
        elif c in "\"'" and (i == 0 or text[i - 1] in " \t[{,:-"):
            quote = c
        i += 1
    return len(text)


def _double_quoted(body: str, line: int) -> str:
    out = []
    i = 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        if i + 1 >= len(body):
            raise YamlError("a backslash at the end of a quoted string", line)
        e = body[i + 1]
        if e in _ESCAPES:
            out.append(_ESCAPES[e])
            i += 2
        elif e in _HEX_ESCAPES:
            n = _HEX_ESCAPES[e]
            digits = body[i + 2 : i + 2 + n]
            if len(digits) != n or not re.fullmatch(r"[0-9A-Fa-f]+", digits):
                raise YamlError(f"a bad \\{e} escape", line)
            out.append(chr(int(digits, 16)))
            i += 2 + n
        else:
            raise YamlError(f"an unknown escape \\{e}", line)
    return "".join(out)


def _quoted(text: str, line: int) -> tuple[str, int]:
    """A quoted scalar at the start of ``text``: its value, and where it ends."""
    q = text[0]
    i = 1
    while i < len(text):
        c = text[i]
        if q == '"' and c == "\\":
            i += 2
            continue
        if c == q:
            if q == "'" and i + 1 < len(text) and text[i + 1] == "'":
                i += 2
                continue
            body = text[1:i]
            if q == "'":
                return body.replace("''", "'"), i + 1
            return _double_quoted(body, line), i + 1
        i += 1
    raise YamlError("a quoted string that does not end on its line", line)


def _key_split(content: str) -> tuple[str, str] | None:
    """(key, rest) if a line's content is "key: rest" (a quoted key, or a
    plain one up to the first ": " or a final ":"), else None. A line
    starting with [ or { is a flow collection, not a key."""
    if content.startswith(("'", '"')):
        try:
            _, end = _quoted(content, 0)
        except YamlError:
            return None
        rest = content[end:].lstrip(" ")
        if rest.startswith(":") and (len(rest) == 1 or rest[1] == " "):
            return content[:end], rest[1:].strip()
        return None
    if content.startswith(("[", "{")):
        return None  # a flow collection
    # A plain key cannot hold ": ", but may hold brackets ("0]: x"): the
    # first ": " (or a final ":") ends it.
    at = content.find(": ")
    if at < 0:
        if not content.endswith(":"):
            return None
        at = len(content) - 1
    key = content[:at].rstrip()
    return (key, content[at + 1 :].strip()) if key else None


class _Parser:
    def __init__(self, text: str) -> None:
        text = text.removeprefix("﻿").replace("\r\n", "\n")
        self.lines = text.split("\n")
        self.ends_with_newline = text.endswith("\n")
        self.anchors: dict[str, Node] = {}
        self.aliases = 0
        self.i = 0

    # -- lines ---------------------------------------------------------------

    def content(self, i: int) -> str:
        line = self.lines[i]
        body = line.lstrip(" ")
        return body[: _comment_start(body)].rstrip()

    def indent(self, i: int) -> int:
        line = self.lines[i]
        n = len(line) - len(line.lstrip(" "))
        if line[n : n + 1] == "\t" and self.content(i):
            raise YamlError("a tab used for indentation", i + 1)
        return n

    def next_content(self, i: int) -> int:
        """The next line at or after ``i`` with content (len(lines) if none)."""
        while i < len(self.lines):
            if self.content(i):
                c = self.content(i)
                if c in ("---", "...") or c.startswith(("--- ", "%")):
                    raise YamlError("several documents, or a directive", i + 1)
                return i
            i += 1
        return i

    # -- nodes ---------------------------------------------------------------

    def document(self) -> Node | None:
        i = 0
        while i < len(self.lines) and not self.content(i):
            i += 1
        if i < len(self.lines) and self.content(i) == "---":
            i += 1
        start = self.next_content(i)
        if start == len(self.lines):
            return None
        node = self.block(start, self.indent(start), 0)
        rest = self.next_content(self.i)
        if rest < len(self.lines):
            raise YamlError("unexpected content (check the indentation)", rest + 1)
        return node

    def block(self, i: int, indent: int, depth: int) -> Node:
        """The node starting at line ``i``, whose lines are at ``indent``."""
        if depth > _MAX_DEPTH:
            raise YamlError("nested too deeply", i + 1)
        content = self.content(i)
        if content == "-" or content.startswith("- "):
            return self.sequence(i, indent, depth)
        if content.startswith("? "):
            raise YamlError("complex (?) keys are not read", i + 1)
        if _key_split(content) is not None:
            return self.mapping(i, indent, depth)
        # A scalar on its own (a whole document, or a sequence item).
        node = self.inline(content, i, indent - 1, depth)
        return node

    def sequence(self, i: int, indent: int, depth: int) -> Node:
        items: list[Node] = []
        start = i
        while i < len(self.lines) and self.indent(i) == indent:
            content = self.content(i)
            if not (content == "-" or content.startswith("- ")):
                break
            rest = content[1:].lstrip(" ")
            if not rest:
                nxt = self.next_content(i + 1)
                if nxt < len(self.lines) and self.indent(nxt) > indent:
                    items.append(self.block(nxt, self.indent(nxt), depth + 1))
                else:
                    items.append(Node("", i + 1))
                    self.i = i + 1
            else:
                # The item's content as a line of its own, at its column:
                # "  - key: v" becomes "    key: v".
                line = self.lines[i]
                column = indent + 1
                while line[column] == " ":
                    column += 1
                self.lines[i] = " " * column + line[column:]
                items.append(self.item(i, column, depth + 1))
            i = self.next_content(self.i)
        self.i = i
        return Node(items, start + 1)

    def item(self, i: int, column: int, depth: int) -> Node:
        content = self.content(i)
        m = _ANCHOR.match(content)
        if not (content.startswith("&") and m):
            return self.block(i, column, depth)
        anchor = m.group(1)
        rest = content[m.end() :].lstrip(" ")
        if not rest:
            nxt = self.next_content(i + 1)
            if nxt < len(self.lines) and self.indent(nxt) >= column:
                return self.remember(anchor, self.block(nxt, self.indent(nxt), depth))
            self.i = i + 1
            return self.remember(anchor, Node("", i + 1))
        if _key_split(rest) is not None or rest.startswith("- "):
            raise YamlError("an anchor before a key on the same line", i + 1)
        return self.remember(anchor, self.inline(rest, i, column - 1, depth))

    def remember(self, anchor: str, node: Node) -> Node:
        self.anchors[anchor] = node
        return node

    def mapping(self, i: int, indent: int, depth: int) -> Node:
        entries: dict[str, Node] = {}
        merged: list[Node] = []
        start = i
        while i < len(self.lines) and self.indent(i) == indent:
            content = self.content(i)
            split = _key_split(content)
            if split is None:
                if content == "-" or content.startswith("- "):
                    raise YamlError("a sequence item where a key was expected", i + 1)
                raise YamlError("a line that is not a key: value", i + 1)
            raw_key, rest = split
            if raw_key.startswith(("'", '"')):
                key = _quoted(raw_key, i + 1)[0]
            else:
                if raw_key[0] in "&*!|>%@`[{,":
                    raise YamlError(f"a key starting with {raw_key[0]!r}", i + 1)
                key = raw_key
            value = self.value(rest, i, indent, depth + 1)
            if key == "<<" and not raw_key.startswith(("'", '"')):
                merged.append(value)
            elif key in entries:
                raise YamlError(f"the key {key!r} twice", i + 1)
            else:
                entries[key] = value
            i = self.next_content(self.i)
        self.i = i
        if merged:
            entries = self.merge(merged, entries, start + 1)
        return Node(entries, start + 1)

    def merge(
        self, sources: list[Node], explicit: dict[str, Node], line: int
    ) -> dict[str, Node]:
        maps: list[dict[str, Node]] = []
        for source in sources:
            items = source.value if isinstance(source.value, list) else [source]
            for item in items:
                if not isinstance(item.value, dict):
                    raise YamlError("<< must name mappings", line)
                maps.append(item.value)
        result: dict[str, Node] = {}
        for m in reversed(maps):  # earlier sources win over later ones
            result.update(m)
        result.update(explicit)  # and the mapping's own keys over both
        return result

    def value(self, rest: str, i: int, indent: int, depth: int) -> Node:
        """A mapping value: ``rest`` after "key:" on line ``i`` (whose key
        is at ``indent``), or the block below it."""
        anchor = None
        m = _ANCHOR.match(rest)
        if rest.startswith("&") and m:
            anchor = m.group(1)
            rest = rest[m.end() :].lstrip(" ")
        if not rest:
            nxt = self.next_content(i + 1)
            node: Node
            if nxt < len(self.lines) and self.indent(nxt) > indent:
                node = self.block(nxt, self.indent(nxt), depth)
            elif (
                nxt < len(self.lines)
                and self.indent(nxt) == indent
                and (self.content(nxt) == "-" or self.content(nxt).startswith("- "))
            ):
                node = self.sequence(nxt, indent, depth)
            else:
                node = Node("", i + 1)
                self.i = i + 1
        else:
            node = self.inline(rest, i, indent, depth)
        return self.remember(anchor, node) if anchor else node

    def inline(self, rest: str, i: int, indent: int, depth: int) -> Node:
        """A value written on line ``i``: an alias, a block scalar, a flow
        collection, a quoted or a plain scalar."""
        line = i + 1
        first = rest[0]
        if first == "*":
            m = _ANCHOR.match(rest)
            if not m or m.end() != len(rest):
                raise YamlError("an alias followed by more text", line)
            if m.group(1) not in self.anchors:
                raise YamlError(f"an alias to an unknown anchor {m.group(1)!r}", line)
            self.aliases += 1
            if self.aliases > _MAX_ALIASES:
                raise YamlError("too many aliases", line)
            self.i = i + 1
            return self.anchors[m.group(1)]
        if first == "!":
            raise YamlError("tags are not read", line)
        if first in "|>":
            return self.block_scalar(rest, i, indent)
        if first in "[{":
            return self.flow_lines(i, rest, depth)
        if first in "'\"":
            value, end = _quoted(rest, line)
            if rest[end:].strip():
                raise YamlError("text after a quoted string", line)
            self.i = i + 1
            return Node(value, line)
        if (
            first in "%@`]},#"
            or rest.startswith(("- ", "? ", ": "))
            or rest in ("-", "?", ":")
        ):
            raise YamlError(f"a plain value starting with {first!r}", line)
        # A plain scalar, perhaps continued on more-indented lines.
        parts = [rest]
        j = i + 1
        while j < len(self.lines):
            if not self.lines[j].strip():
                k = self.next_content(j)
                if k < len(self.lines) and self.indent(k) > indent:
                    raise YamlError("a blank line inside a plain value", j + 1)
                break
            if self.indent(j) <= indent:
                break
            content = self.content(j)
            if not content:  # a comment line ends the value
                break
            parts.append(content)
            j += 1
        text = " ".join(parts)
        if ": " in text or text.endswith(":"):
            raise YamlError("a plain value containing ': '", line)
        self.i = j
        return Node(text, line)

    def block_scalar(self, header: str, i: int, indent: int) -> Node:
        line = i + 1
        m = re.fullmatch(r"([|>])([-+]?)", header)
        if not m:
            raise YamlError("a block scalar header that is not read", line)
        folded = m.group(1) == ">"
        chomp = m.group(2)
        # The scalar's lines: everything more indented than the key, and
        # blank lines among them.
        j = i + 1
        body: list[str] = []
        content_indent = None
        while j < len(self.lines):
            raw = self.lines[j]
            if not raw.strip():
                body.append(raw)
                j += 1
                continue
            n = len(raw) - len(raw.lstrip(" "))
            if content_indent is None:
                if n <= indent:
                    break
                content_indent = n
            elif n < content_indent:
                break
            body.append(raw)
            j += 1
        if content_indent is None:
            self.i = j
            return Node("", line)
        # Trailing blank lines belong to the scalar only for "+".
        while body and not body[-1].strip():
            body.pop()
            j -= 1
        trailing = 0
        k = j
        while k < len(self.lines) and not self.lines[k].strip():
            trailing += 1
            k += 1
        at_end = k == len(self.lines)
        if at_end and trailing:
            # The last split piece of a text ending in "\n" is "", not a line.
            trailing -= 1 if self.ends_with_newline else 0
        lines: list[str] = []
        for raw in body:
            if raw.strip() or len(raw) > content_indent:
                lines.append(raw[content_indent:])
            else:
                lines.append("")
        chunks: list[str] = []
        breaks = 0
        n = 0
        while n < len(lines):
            # Leading blank lines, and those between content lines.
            while n < len(lines) and lines[n] == "":
                breaks += 1
                n += 1
            if n == len(lines):
                break
            text = lines[n]
            chunks.append("\n" * breaks)
            chunks.append(text)
            n += 1
            breaks = 0
            while n < len(lines) and lines[n] == "":
                breaks += 1
                n += 1
            if n < len(lines):
                nxt = lines[n]
                if folded and text[0] not in " \t" and nxt[0] not in " \t":
                    if not breaks:
                        chunks.append(" ")
                else:
                    chunks.append("\n")
        last_has_break = not (at_end and k == j and not self.ends_with_newline)
        if chomp != "-" and last_has_break:
            chunks.append("\n")
        if chomp == "+":
            chunks.append("\n" * (breaks + trailing))
        self.i = j
        return Node("".join(chunks), line)

    # -- flow ----------------------------------------------------------------

    def flow_lines(self, i: int, rest: str, depth: int) -> Node:
        """A flow collection starting with ``rest`` on line ``i`` and
        perhaps continuing on the next lines."""
        text = rest
        j = i
        while True:
            parser = _Flow(text, i + 1, self, depth)
            try:
                node = parser.parse()
            except _Incomplete:
                j += 1
                if j >= len(self.lines):
                    raise YamlError("a [ or { that is never closed", i + 1) from None
                text += " " + self.content(j)
                continue
            if parser.pos != len(text):
                raise YamlError("text after a flow collection", j + 1)
            self.i = j + 1
            return node


class _Incomplete(Exception):
    pass


class _Flow:
    """A flow collection, all on one (joined) line."""

    def __init__(self, text: str, line: int, owner: _Parser, depth: int) -> None:
        self.text = text
        self.pos = 0
        self.line = line
        self.owner = owner
        self.depth = depth

    def skip(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos] == " ":
            self.pos += 1

    def peek(self) -> str:
        self.skip()
        if self.pos >= len(self.text):
            raise _Incomplete
        return self.text[self.pos]

    def parse(self) -> Node:
        node = self.node(self.depth)
        self.skip()
        return node

    def node(self, depth: int) -> Node:
        if depth > _MAX_DEPTH:
            raise YamlError("nested too deeply", self.line)
        c = self.peek()
        if c == "[":
            return self.collection("]", depth)
        if c == "{":
            return self.collection("}", depth)
        if c in "'\"":
            value, end = _quoted(self.text[self.pos :], self.line)
            self.pos += end
            return Node(value, self.line)
        if c == "*":
            m = _ANCHOR.match(self.text, self.pos)
            if m is None:
                raise YamlError("an alias with no name", self.line)
            self.pos = m.end()
            name = m.group(1)
            if name not in self.owner.anchors:
                raise YamlError(f"an alias to an unknown anchor {name!r}", self.line)
            return self.owner.anchors[name]
        if c in "&!":
            raise YamlError(
                "anchors and tags inside [ ] or { } are not read", self.line
            )
        if c == "?" and self.text[self.pos + 1 : self.pos + 2] in (" ", ""):
            raise YamlError("complex (?) keys are not read", self.line)
        start = self.pos
        while self.pos < len(self.text):
            ch = self.text[self.pos]
            if ch in ",[]{}":
                break
            if ch == ":" and (
                self.pos + 1 == len(self.text) or self.text[self.pos + 1] in " ,[]{}"
            ):
                break
            if ch == "#" and self.pos > 0 and self.text[self.pos - 1] == " ":
                raise YamlError("a comment inside [ ] or { }", self.line)
            self.pos += 1
        return Node(self.text[start : self.pos].strip(), self.line)

    def collection(self, close: str, depth: int) -> Node:
        self.pos += 1
        is_map = close == "}"
        items: list[Node] = []
        entries: dict[str, Node] = {}
        while True:
            c = self.peek()
            if c == close:
                self.pos += 1
                break
            item = self.node(depth + 1)
            if is_map:
                if not isinstance(item.value, str):
                    raise YamlError("a key that is not a scalar", self.line)
                c = self.peek()
                if c == ":":
                    self.pos += 1
                    c = self.peek()
                    value = Node("", self.line) if c in ",}" else self.node(depth + 1)
                else:
                    value = Node("", self.line)
                if item.value in entries:
                    raise YamlError(f"the key {item.value!r} twice", self.line)
                entries[item.value] = value
            else:
                if self.peek() == ":":
                    raise YamlError("key: value inside [ ] is not read", self.line)
                items.append(item)
            c = self.peek()
            if c == ",":
                self.pos += 1
            elif c != close:
                raise YamlError(f"expected , or {close}", self.line)
        if is_map:
            return Node(entries, self.line)
        return Node(items, self.line)


def load(text: str) -> Node | None:
    """The document in ``text`` (None if it is empty)."""
    return _Parser(text).document()
