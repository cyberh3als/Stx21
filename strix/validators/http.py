"""Minimal raw-HTTP message parsing for evidence blocks.

Agents paste exchanges as text (often inside markdown fences, sometimes
reformatted by tools like curl -i). Parsing is deliberately forgiving but never
guesses: anything unparsable yields an empty field and the validator fails
closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit


_FENCE_RE = re.compile(r"^\s*```[^\n]*\n(.*?)\n?```\s*$", re.DOTALL)
_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.IGNORECASE)
_REQUEST_RE = re.compile(r"^([A-Z]{3,10})\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?\s*$")


@dataclass
class Message:
    raw: str = ""
    status: int | None = None
    method: str | None = None
    target: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()


def _strip_fence(text: str) -> str:
    match = _FENCE_RE.match(text)
    return match.group(1) if match else text


def parse(raw: object) -> Message:
    """Parse a raw HTTP request or response; non-strings give an empty Message."""
    if not isinstance(raw, str) or not raw.strip():
        return Message()
    text = _strip_fence(raw.replace("\r\n", "\n")).lstrip("\n")
    head, sep, body = text.partition("\n\n")
    if not sep:
        head, body = text, ""
    lines = head.split("\n")
    msg = Message(raw=text, body=body)

    first = lines[0].strip()
    status = _STATUS_RE.match(first)
    request = _REQUEST_RE.match(first)
    if status:
        msg.status = int(status.group(1))
        header_lines = lines[1:]
    elif request:
        msg.method, msg.target = request.group(1), request.group(2)
        header_lines = lines[1:]
    else:
        # Headers-less / body-only paste: treat everything as the body.
        msg.body = text
        return msg

    for line in header_lines:
        name, colon, value = line.partition(":")
        if colon and name.strip():
            msg.headers.setdefault(name.strip().lower(), value.strip())
    return msg


def request_host(request: Message) -> str | None:
    host = request.headers.get("host")
    if host:
        return host.split(":")[0].lower()
    if request.target:
        return (urlsplit(request.target).hostname or "").lower() or None
    return None
