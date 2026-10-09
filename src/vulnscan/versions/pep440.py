"""Python versions (PEP 440): parsing, normalising, ordering.

A version is ``[N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local]``, written with
some freedom: "1.0-ALPHA.1", "1.0a1" and "v1.0.0a1" are the same version
(case, separators and a leading "v" do not matter; "alpha", "beta", "c",
"pre" and "preview" are spellings of a, b and rc; "-1" is a post-release).
The pattern below is PEP 440's own (its appendix), to accept exactly what
it accepts.

Ordering, as the PEP defines it: epoch, then the release numbers (trailing
zeros do not count: 1.0 == 1.0.0), then a dev release of a final release
before its pre-releases, pre-releases before the final, post-releases after
it, a dev release just before what it is a dev release of, and a local
version just after the same version without one. ``key`` turns a version
into a tuple that sorts that way.
"""

import re
from dataclasses import dataclass

_PATTERN = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>
        [-_.]?
        (?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)
        [-_.]?
        (?P<pre_n>[0-9]+)?
    )?
    (?P<post>
        (?:-(?P<post_n1>[0-9]+))
        |
        (?:
            [-_.]?
            (?P<post_l>post|rev|r)
            [-_.]?
            (?P<post_n2>[0-9]+)?
        )
    )?
    (?P<dev>
        [-_.]?
        (?P<dev_l>dev)
        [-_.]?
        (?P<dev_n>[0-9]+)?
    )?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)

_PRE = {
    "a": "a",
    "alpha": "a",
    "b": "b",
    "beta": "b",
    "rc": "rc",
    "c": "rc",
    "pre": "rc",
    "preview": "rc",
}
_PRE_RANK = {"a": 0, "b": 1, "rc": 2}


@dataclass(frozen=True)
class Version:
    epoch: int
    release: tuple[int, ...]
    pre: tuple[str, int] | None
    post: int | None
    dev: int | None
    local: tuple[str | int, ...] | None

    def __str__(self) -> str:
        """The normalised form: "1.0rc1.post2.dev3+ubuntu.1"."""
        text = (f"{self.epoch}!" if self.epoch else "") + ".".join(
            map(str, self.release)
        )
        if self.pre is not None:
            text += f"{self.pre[0]}{self.pre[1]}"
        if self.post is not None:
            text += f".post{self.post}"
        if self.dev is not None:
            text += f".dev{self.dev}"
        if self.local is not None:
            text += "+" + ".".join(map(str, self.local))
        return text


def parse(text: str) -> Version | None:
    """A version, or None if ``text`` is not one PEP 440 accepts."""
    m = _PATTERN.match(text)
    if m is None:
        return None
    pre = None
    if m["pre_l"]:
        pre = (_PRE[m["pre_l"].lower()], int(m["pre_n"] or 0))
    post = None
    if m["post_n1"]:
        post = int(m["post_n1"])
    elif m["post_l"]:
        post = int(m["post_n2"] or 0)
    dev = int(m["dev_n"] or 0) if m["dev_l"] else None
    local = None
    if m["local"]:
        local = tuple(
            int(part) if part.isdigit() else part.lower()
            for part in re.split(r"[-_.]", m["local"])
        )
    return Version(
        epoch=int(m["epoch"] or 0),
        release=tuple(int(n) for n in m["release"].split(".")),
        pre=pre,
        post=post,
        dev=dev,
        local=local,
    )


# Sort keys use (rank, value) pairs, so "missing" can sort before or after
# every real value without mixing types in one comparison.
_BEFORE_ALL = -1
_AFTER_ALL = 1


def key(version: Version) -> tuple[object, ...]:
    release = list(version.release)
    while len(release) > 1 and release[-1] == 0:
        release.pop()  # 1.0.0 == 1.0
    if version.pre is None and version.post is None and version.dev is not None:
        pre: tuple[int, int, int] = (_BEFORE_ALL, 0, 0)  # 1.0.dev1 < 1.0a1
    elif version.pre is None:
        pre = (_AFTER_ALL, 0, 0)  # 1.0rc1 < 1.0
    else:
        pre = (0, _PRE_RANK[version.pre[0]], version.pre[1])
    post = (_BEFORE_ALL, 0) if version.post is None else (0, version.post)
    dev = (_AFTER_ALL, 0) if version.dev is None else (0, version.dev)
    if version.local is None:
        local: tuple[object, ...] = (_BEFORE_ALL,)
    else:
        # Within a local version, a word sorts before a number.
        local = (
            0,
            tuple(
                (1, part, "") if isinstance(part, int) else (0, 0, part)
                for part in version.local
            ),
        )
    return (version.epoch, tuple(release), pre, post, dev, local)
