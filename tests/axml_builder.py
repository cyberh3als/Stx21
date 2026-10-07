"""Test helper: encode a small XML tree as Android binary XML (AXML).

Implemented from the public AOSP ResourceTypes format so tests can exercise the
decoder without a real APK. Supports string, boolean and integer attributes.
"""

from __future__ import annotations

import struct
from typing import Any


ANDROID_NS = "http://schemas.android.com/apk/res/android"
_NO_ENTRY = 0xFFFFFFFF


class _Pool:
    def __init__(self, utf8: bool) -> None:
        self.utf8 = utf8
        self.items: list[str] = []

    def index(self, value: str) -> int:
        if value not in self.items:
            self.items.append(value)
        return self.items.index(value)

    def encode(self) -> bytes:
        blobs = []
        for s in self.items:
            if self.utf8:
                raw = s.encode("utf-8")
                blobs.append(bytes([len(s)]) + bytes([len(raw)]) + raw + b"\x00")
            else:
                raw = s.encode("utf-16-le")
                blobs.append(struct.pack("<H", len(s)) + raw + b"\x00\x00")
        offsets, body = [], b""
        for blob in blobs:
            offsets.append(len(body))
            body += blob
        while len(body) % 4:
            body += b"\x00"
        header_size = 28
        strings_start = header_size + 4 * len(offsets)
        chunk_size = strings_start + len(body)
        flags = 0x100 if self.utf8 else 0
        out = struct.pack("<HHI", 0x0001, header_size, chunk_size)
        out += struct.pack("<IIIII", len(self.items), 0, flags, strings_start, 0)
        out += b"".join(struct.pack("<I", o) for o in offsets) + body
        return out


def build(root: tuple[Any, ...], *, utf8: bool = False, strip_names: bool = False) -> bytes:
    """``root`` is ``(tag, {attr: value}, [children])``; attr ``android:x`` uses the android ns.

    With ``strip_names`` attribute names are replaced by resource ids only
    (as some obfuscators do) for the handful of ids the decoder knows.
    """
    pool = _Pool(utf8)
    res_ids = {
        "name": 0x01010003,
        "permission": 0x01010006,
        "debuggable": 0x0101000F,
        "exported": 0x01010010,
        "allowBackup": 0x01010280,
        "usesCleartextTraffic": 0x010104EC,
    }
    ordered_names: list[str] = []

    # Resource-mapped attribute names must come first in the pool.
    def collect(node: tuple[Any, ...]) -> None:
        for key in node[1]:
            name = key.split(":", 1)[1] if key.startswith("android:") else key
            if name in res_ids and name not in ordered_names:
                ordered_names.append(name)
        for child in node[2]:
            collect(child)

    collect(root)
    resource_map = []
    for name in ordered_names:
        pool.index("" if strip_names else name)
        resource_map.append(res_ids[name])
    if strip_names:
        # keep indices distinct: the empty string is index 0, so pad placeholders
        pool.items = [f"_n{i}" for i in range(len(ordered_names))]
        pool.items = ["" for _ in ordered_names]
    prefix_idx, uri_idx = pool.index("android"), pool.index(ANDROID_NS)
    body = b""

    def emit(node: tuple[Any, ...]) -> None:
        nonlocal body
        tag, attrs, children = node
        attr_bytes = b""
        for key, value in attrs.items():
            ns = uri_idx if key.startswith("android:") else _NO_ENTRY
            name = key.split(":", 1)[1] if key.startswith("android:") else key
            if strip_names and name in ordered_names:
                name_idx = ordered_names.index(name)
            else:
                name_idx = pool.index(name)
            if isinstance(value, bool):
                raw, dtype, data = _NO_ENTRY, 0x12, 0xFFFFFFFF if value else 0
            elif isinstance(value, int):
                raw, dtype, data = _NO_ENTRY, 0x10, value & 0xFFFFFFFF
            else:
                idx = pool.index(str(value))
                raw, dtype, data = idx, 0x03, idx
            attr_bytes += struct.pack("<IIIHBBI", ns, name_idx, raw, 8, 0, dtype, data)
        tag_idx = pool.index(tag)
        size = 36 + len(attr_bytes)
        body += struct.pack("<HHIII", 0x0102, 16, size, 1, _NO_ENTRY)
        body += struct.pack("<IIHHHHHH", _NO_ENTRY, tag_idx, 20, 20, len(attrs), 0, 0, 0)
        body += attr_bytes
        for child in children:
            emit(child)
        body += struct.pack("<HHIII", 0x0103, 16, 24, 1, _NO_ENTRY)
        body += struct.pack("<II", _NO_ENTRY, tag_idx)

    ns_start = struct.pack("<HHIII", 0x0100, 16, 24, 1, _NO_ENTRY) + struct.pack(
        "<II", prefix_idx, uri_idx
    )
    ns_end = struct.pack("<HHIII", 0x0101, 16, 24, 1, _NO_ENTRY) + struct.pack(
        "<II", prefix_idx, uri_idx
    )
    emit(root)
    pool_bytes = pool.encode()
    res_bytes = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(resource_map)) + b"".join(
        struct.pack("<I", r) for r in resource_map
    )
    inner = pool_bytes + res_bytes + ns_start + body + ns_end
    return struct.pack("<HHI", 0x0003, 8, 8 + len(inner)) + inner
