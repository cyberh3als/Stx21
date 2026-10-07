"""Decoder for Android binary XML (AXML), as used by AndroidManifest.xml.

Pure Python and read-only: input is untrusted (it is the app under test), so
every offset and length is bounds-checked and the decoder raises
:class:`AxmlError` on anything malformed instead of guessing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


ANDROID_NS = "http://schemas.android.com/apk/res/android"

_CHUNK_XML = 0x0003
_CHUNK_STRING_POOL = 0x0001
_CHUNK_RESOURCE_MAP = 0x0180
_CHUNK_START_NS = 0x0100
_CHUNK_END_NS = 0x0101
_CHUNK_START_ELEMENT = 0x0102
_CHUNK_END_ELEMENT = 0x0103

_UTF8_FLAG = 0x100
_TYPE_REFERENCE = 0x01
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12

MAX_ELEMENT_DEPTH = 256
MAX_STRINGS = 500_000

# Attribute resource ids, used only when an obfuscator stripped attribute names.
_ATTR_BY_RESOURCE_ID = {
    0x01010003: "name",
    0x01010006: "permission",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x0101020C: "minSdkVersion",
    0x01010270: "targetSdkVersion",
    0x01010280: "allowBackup",
    0x010104EC: "usesCleartextTraffic",
    0x01010527: "networkSecurityConfig",
}


class AxmlError(ValueError):
    """Raised when the binary XML is malformed or exceeds safety limits."""


@dataclass
class Node:
    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    children: list[Node] = field(default_factory=list)

    def iter(self) -> list[Node]:
        out = [self]
        for child in self.children:
            out.extend(child.iter())
        return out

    def find_all(self, tag: str) -> list[Node]:
        return [n for n in self.iter() if n.tag == tag]

    def get(self, name: str, default: str | None = None) -> str | None:
        """Attribute lookup that treats ``android:name`` and ``name`` alike."""
        return self.attrs.get(f"android:{name}", self.attrs.get(name, default))


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise AxmlError("read past end of data")
    return int(struct.unpack_from("<H", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise AxmlError("read past end of data")
    return int(struct.unpack_from("<I", data, offset)[0])


def _read_utf8_len(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first & 0x80:
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _read_string(data: bytes, pool_start: int, strings_start: int, offset: int, utf8: bool) -> str:
    pos = pool_start + strings_start + offset
    if pos < 0 or pos >= len(data):
        raise AxmlError("string offset out of range")
    try:
        if utf8:
            _, pos = _read_utf8_len(data, pos)
            byte_len, pos = _read_utf8_len(data, pos)
            return data[pos : pos + byte_len].decode("utf-8", errors="replace")
        length = _u16(data, pos)
        pos += 2
        if length & 0x8000:
            length = ((length & 0x7FFF) << 16) | _u16(data, pos)
            pos += 2
        return data[pos : pos + length * 2].decode("utf-16-le", errors="replace")
    except IndexError as exc:
        raise AxmlError("truncated string") from exc


def _parse_string_pool(data: bytes, start: int, size: int) -> list[str]:
    string_count = _u32(data, start + 8)
    flags = _u32(data, start + 16)
    strings_start = _u32(data, start + 20)
    if string_count > MAX_STRINGS:
        raise AxmlError("string pool too large")
    offsets_at = start + _u16(data, start + 2)
    if offsets_at + string_count * 4 > start + size:
        raise AxmlError("string offsets exceed chunk")
    utf8 = bool(flags & _UTF8_FLAG)
    return [
        _read_string(data, start, strings_start, _u32(data, offsets_at + i * 4), utf8)
        for i in range(string_count)
    ]


def _attr_value(  # noqa: PLR0911
    strings: list[str], raw: int, data_type: int, value: int
) -> str:
    if data_type == _TYPE_STRING:
        return strings[value] if value < len(strings) else ""
    if raw != 0xFFFFFFFF and raw < len(strings):
        return strings[raw]
    if data_type == _TYPE_INT_BOOLEAN:
        return "true" if value != 0 else "false"
    if data_type == _TYPE_INT_HEX:
        return f"0x{value:x}"
    if data_type == _TYPE_REFERENCE:
        return f"@0x{value:x}"
    if data_type == _TYPE_INT_DEC:
        return str(struct.unpack("<i", struct.pack("<I", value))[0])
    return str(value)


def _parse_start_element(
    data: bytes,
    pos: int,
    chunk_size: int,
    strings: list[str],
    resource_ids: list[int],
    namespaces: dict[str, str],
) -> Node:
    name_idx = _u32(data, pos + 20)
    attr_start = _u16(data, pos + 24)
    attr_size = _u16(data, pos + 26)
    attr_count = _u16(data, pos + 28)
    if attr_size < 20 or pos + 16 + attr_start + attr_count * attr_size > pos + chunk_size:
        raise AxmlError("attributes exceed chunk")
    node = Node(tag=strings[name_idx] if name_idx < len(strings) else "")
    for i in range(attr_count):
        at = pos + 16 + attr_start + i * attr_size
        ns_idx, nm_idx, raw = _u32(data, at), _u32(data, at + 4), _u32(data, at + 8)
        data_type, value = data[at + 15], _u32(data, at + 16)
        name = strings[nm_idx] if nm_idx < len(strings) else ""
        if not name and nm_idx < len(resource_ids):
            name = _ATTR_BY_RESOURCE_ID.get(resource_ids[nm_idx], "")
        if not name:
            continue
        ns_uri = strings[ns_idx] if ns_idx < len(strings) else ""
        prefix = namespaces.get(ns_uri, "android" if ns_uri == ANDROID_NS else "")
        key = f"{prefix}:{name}" if prefix else name
        node.attrs[key] = _attr_value(strings, raw, data_type, value)
    return node


def decode(data: bytes) -> Node:  # noqa: PLR0912
    """Decode binary XML into a :class:`Node` tree (root element)."""
    if len(data) < 8 or _u16(data, 0) != _CHUNK_XML:
        raise AxmlError("not Android binary XML")
    strings: list[str] = []
    resource_ids: list[int] = []
    namespaces: dict[str, str] = {}
    stack: list[Node] = []
    root: Node | None = None

    pos = _u16(data, 2)
    end = min(_u32(data, 4), len(data))
    while pos + 8 <= end:
        chunk_type, chunk_size = _u16(data, pos), _u32(data, pos + 4)
        if chunk_size < 8 or pos + chunk_size > end:
            raise AxmlError("chunk size out of range")
        if chunk_type == _CHUNK_STRING_POOL:
            strings = _parse_string_pool(data, pos, chunk_size)
        elif chunk_type == _CHUNK_RESOURCE_MAP:
            resource_ids = [_u32(data, pos + 8 + i * 4) for i in range((chunk_size - 8) // 4)]
        elif chunk_type == _CHUNK_START_NS:
            prefix_idx, uri_idx = _u32(data, pos + 16), _u32(data, pos + 20)
            if prefix_idx < len(strings) and uri_idx < len(strings):
                namespaces[strings[uri_idx]] = strings[prefix_idx]
        elif chunk_type == _CHUNK_START_ELEMENT:
            if len(stack) >= MAX_ELEMENT_DEPTH:
                raise AxmlError("element nesting too deep")
            node = _parse_start_element(data, pos, chunk_size, strings, resource_ids, namespaces)
            if stack:
                stack[-1].children.append(node)
            elif root is None:
                root = node
            stack.append(node)
        elif chunk_type == _CHUNK_END_ELEMENT and stack:
            stack.pop()
        pos += chunk_size
    if root is None:
        raise AxmlError("no root element")
    return root


def to_xml(node: Node, indent: int = 0) -> str:
    """Render a decoded tree as well-formed XML (used as finding evidence)."""
    pad = "  " * indent
    attrs = "".join(f' {k}="{_escape(v)}"' for k, v in node.attrs.items())
    if indent == 0 and any(k.startswith("android:") for n in node.iter() for k in n.attrs):
        attrs += f' xmlns:android="{ANDROID_NS}"'
    if not node.children:
        return f"{pad}<{node.tag}{attrs}/>"
    inner = "\n".join(to_xml(c, indent + 1) for c in node.children)
    return f"{pad}<{node.tag}{attrs}>\n{inner}\n{pad}</{node.tag}>"


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    )
