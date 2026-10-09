"""Downloading OSV's exports: the only network VulnScan ever uses.

One zip of JSON advisories per ecosystem, from OSV's public bucket. The
download is streamed to a ``.part`` file and hashed as it arrives; it is
kept only if its length matches the server's and its MD5 matches the one
the server publishes for the object (Google Cloud Storage's x-goog-hash
header), so a truncated or damaged download is never indexed. The SHA-256
is recorded with the snapshot, to say exactly which data a scan used.
"""

import base64
import hashlib
import http.client
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from vulnscan import __version__

EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
CHUNK = 1 << 20


class FetchError(Exception):
    pass


@dataclass(frozen=True)
class Downloaded:
    path: Path
    bytes: int
    sha256: str
    md5_checked: bool
    last_modified: str | None


def download(url: str, dest: Path, timeout: float = 60.0) -> Downloaded:
    part = dest.with_name(dest.name + ".part")
    request = urllib.request.Request(
        url, headers={"User-Agent": f"vulnscan/{__version__}"}
    )
    sha256, md5, size = hashlib.sha256(), hashlib.md5(), 0
    try:
        with (
            urllib.request.urlopen(request, timeout=timeout) as response,
            part.open("wb") as out,
        ):
            expected_length = response.headers.get("Content-Length")
            published_md5 = None
            for value in response.headers.get_all("x-goog-hash") or []:
                for item in value.split(","):
                    kind, _, digest = item.strip().partition("=")
                    if kind == "md5":
                        published_md5 = digest
            last_modified = response.headers.get("Last-Modified")
            while chunk := response.read(CHUNK):
                out.write(chunk)
                sha256.update(chunk)
                md5.update(chunk)
                size += len(chunk)
    # URLError and HTTPError are OSErrors; a connection cut mid-chunk raises
    # http.client.IncompleteRead, which is not.
    except (OSError, http.client.HTTPException) as error:
        part.unlink(missing_ok=True)
        raise FetchError(f"{url}: {error}") from error
    if expected_length is not None and int(expected_length) != size:
        part.unlink(missing_ok=True)
        raise FetchError(f"{url}: {size} bytes arrived of {expected_length}")
    ours = base64.b64encode(md5.digest()).decode()
    if published_md5 is not None and published_md5 != ours:
        part.unlink(missing_ok=True)
        raise FetchError(
            f"{url}: MD5 {ours} does not match the published {published_md5}"
        )
    part.replace(dest)
    return Downloaded(
        dest, size, sha256.hexdigest(), published_md5 is not None, last_modified
    )


def file_info(path: Path) -> Downloaded:
    """The same record for a zip already on disk (``update --from``)."""
    sha256, size = hashlib.sha256(), 0
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            sha256.update(chunk)
            size += len(chunk)
    return Downloaded(path, size, sha256.hexdigest(), False, None)
