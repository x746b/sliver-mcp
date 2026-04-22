"""Protobuf → dict and base64 helpers."""

from __future__ import annotations

import base64
import json
from typing import Any

from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message


def pb_to_dict(msg: Message | None) -> dict[str, Any]:
    """Convert a protobuf message to a plain dict with readable field names."""
    if msg is None:
        return {}
    return MessageToDict(msg, preserving_proto_field_name=True)


def pb_list_to_dicts(msgs) -> list[dict[str, Any]]:
    return [pb_to_dict(m) for m in (msgs or [])]


def b64e(data: bytes | None) -> str:
    if not data:
        return ""
    return base64.b64encode(data).decode("ascii")


def b64d(data: str | None) -> bytes:
    if not data:
        return b""
    return base64.b64decode(data)


_TEXT_BYTE_FIELDS = {"Stdout", "Stderr", "Output", "Response"}


def decode_text_fields(d: Any) -> Any:
    """Recursively convert base64 bytes fields likely to be text into decoded strings.

    Protobuf bytes fields round-trip as base64 in MessageToDict. For fields we expect
    to be human-readable text (command output), decode and replace the value.
    Binary bytes fields are left as base64 under the original key.
    """
    if isinstance(d, dict):
        for k in list(d.keys()):
            v = d[k]
            if isinstance(v, (dict, list)):
                d[k] = decode_text_fields(v)
            elif isinstance(v, str) and k in _TEXT_BYTE_FIELDS:
                try:
                    raw = base64.b64decode(v, validate=False)
                    text = raw.decode("utf-8", errors="replace")
                    d[k] = text
                except Exception:
                    pass
    elif isinstance(d, list):
        return [decode_text_fields(x) for x in d]
    return d


def fmt(obj: Any) -> str:
    """Pretty-print a dict/list as JSON for MCP tool return."""
    return json.dumps(obj, indent=2, default=str, ensure_ascii=False)


def err(message: str, **extra: Any) -> str:
    payload: dict[str, Any] = {"error": message}
    payload.update(extra)
    return fmt(payload)
