"""Safe, in-memory reading of APK/IPA archives.

The archive is the untrusted app under test, so nothing is extracted to disk
(no path traversal or symlink surface) and reads are capped to defend against
zip bombs.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Self


if TYPE_CHECKING:
    from collections.abc import Iterator


MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024  # 1 GiB on disk
MAX_MEMBERS = 50_000
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_TOTAL_READ_BYTES = 768 * 1024 * 1024


class ArchiveError(ValueError):
    """Raised for unreadable or unsafe archives."""


class AppArchive:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        try:
            size = self.path.stat().st_size
        except OSError as exc:
            raise ArchiveError(f"cannot read {self.path.name}: {exc.strerror}") from exc
        if size > MAX_ARCHIVE_BYTES:
            raise ArchiveError(f"{self.path.name} is larger than {MAX_ARCHIVE_BYTES >> 20} MiB")
        try:
            self._zip = zipfile.ZipFile(self.path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise ArchiveError(f"{self.path.name} is not a valid zip archive") from exc
        if len(self._zip.infolist()) > MAX_MEMBERS:
            raise ArchiveError("archive has too many members")
        self._read_total = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self._zip.close()

    def names(self) -> list[str]:
        return [i.filename for i in self._zip.infolist() if not i.is_dir()]

    def read(self, name: str, limit: int = MAX_MEMBER_BYTES) -> bytes | None:
        """Read one member fully, or ``None`` if absent or over ``limit``."""
        try:
            info = self._zip.getinfo(name)
        except KeyError:
            return None
        if info.file_size > limit or self._read_total + info.file_size > MAX_TOTAL_READ_BYTES:
            return None
        with self._zip.open(info) as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            return None
        self._read_total += len(data)
        return data

    def iter_matching(self, suffixes: tuple[str, ...]) -> Iterator[tuple[str, bytes]]:
        for name in self.names():
            if name.lower().endswith(suffixes):
                data = self.read(name)
                if data is not None:
                    yield name, data
