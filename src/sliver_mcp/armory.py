"""Armory (aliases + extensions) discovery and execution helpers.

Sliver's armory stores installed packages under:
  ~/.sliver-client/aliases/<name>/alias.json        + assembly binaries
  ~/.sliver-client/extensions/<name>/extension.json + BOF/shared-lib binaries

Aliases run via execute_assembly (.NET). Extensions (BOFs, shared libs) run via
RegisterExtension + CallExtension gRPC — not exposed by sliver-py, so we use
the raw _stub with interactive_obj._request() to attach session/beacon context.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

DEFAULT_ARMORY_ROOT = Path.home() / ".sliver-client"


@dataclass
class ArmoryFile:
    os: str
    arch: str
    path: str


@dataclass
class ArmoryArg:
    name: str
    desc: str = ""
    type: str = "string"
    optional: bool = False


@dataclass
class ArmoryEntry:
    kind: str  # "alias" | "extension"
    dir: Path
    name: str
    command_name: str
    version: str = ""
    help: str = ""
    long_help: str = ""
    original_author: str = ""
    extension_author: str = ""
    repo_url: str = ""
    entrypoint: str = ""
    depends_on: str = ""
    allow_args: bool = True
    default_args: str = ""
    is_reflective: bool = False
    is_assembly: bool = True
    files: list[ArmoryFile] = field(default_factory=list)
    arguments: list[ArmoryArg] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def resolve_binary(self, os: str, arch: str) -> Optional[bytes]:
        """Return binary bytes for the matching os/arch, or None."""
        p = self.resolve_path(os, arch)
        return p.read_bytes() if p else None

    def resolve_path(self, os: str, arch: str) -> Optional[Path]:
        """Return filesystem path of matching binary for os/arch."""
        for f in self.files:
            if f.os == os and f.arch == arch:
                p = self.dir / f.path
                if p.exists():
                    return p
        for f in self.files:
            if f.os == os:
                p = self.dir / f.path
                if p.exists():
                    return p
        return None

    def is_bof(self, os: str, arch: str) -> bool:
        """True if the selected binary for the target is a BOF (.o COFF object)."""
        p = self.resolve_path(os, arch)
        return p is not None and p.suffix.lower() == ".o"

    def summary(self) -> dict:
        """Minimal list-view entry (cheap tokens). Use armory_{alias,extension}_info for full manifest."""
        return {
            "command_name": self.command_name,
            "version": self.version,
            "help": self.help[:200],
            "depends_on": self.depends_on,
            "osarch": sorted({f"{f.os}/{f.arch}" for f in self.files if f.os and f.arch}),
            "is_bof": any(f.path.lower().endswith(".o") for f in self.files),
        }

    def full_summary(self) -> dict:
        """Detailed summary with files + URLs; used when the LLM explicitly asks for one entry."""
        return {
            "kind": self.kind,
            "name": self.name,
            "command_name": self.command_name,
            "version": self.version,
            "help": self.help,
            "long_help": self.long_help,
            "repo_url": self.repo_url,
            "files": [{"os": f.os, "arch": f.arch, "path": f.path} for f in self.files],
            "depends_on": self.depends_on,
            "entrypoint": self.entrypoint,
            "arguments": [{"name": a.name, "desc": a.desc, "type": a.type, "optional": a.optional} for a in self.arguments],
        }


def _parse_manifest(path: Path, kind: str) -> Optional[ArmoryEntry]:
    try:
        data = json.loads(path.read_text())
    except Exception:
        return None
    files = [
        ArmoryFile(os=f.get("os", ""), arch=f.get("arch", ""), path=f.get("path", ""))
        for f in data.get("files", [])
    ]
    args = [
        ArmoryArg(
            name=a.get("name", ""),
            desc=a.get("desc", ""),
            type=a.get("type", "string"),
            optional=bool(a.get("optional", False)),
        )
        for a in data.get("arguments", [])
    ]
    return ArmoryEntry(
        kind=kind,
        dir=path.parent,
        name=data.get("name", path.parent.name),
        command_name=data.get("command_name", path.parent.name),
        version=data.get("version", ""),
        help=data.get("help", ""),
        long_help=data.get("long_help", ""),
        original_author=data.get("original_author", ""),
        extension_author=data.get("extension_author", ""),
        repo_url=data.get("repo_url", ""),
        entrypoint=data.get("entrypoint", ""),
        depends_on=data.get("depends_on", ""),
        allow_args=bool(data.get("allow_args", True)),
        default_args=data.get("default_args", ""),
        is_reflective=bool(data.get("is_reflective", False)),
        is_assembly=bool(data.get("is_assembly", True)),
        files=files,
        arguments=args,
        raw=data,
    )


def scan_aliases(root: Path = DEFAULT_ARMORY_ROOT) -> list[ArmoryEntry]:
    d = root / "aliases"
    if not d.exists():
        return []
    out: list[ArmoryEntry] = []
    for child in sorted(d.iterdir()):
        mf = child / "alias.json"
        if mf.exists():
            e = _parse_manifest(mf, "alias")
            if e:
                out.append(e)
    return out


def scan_extensions(root: Path = DEFAULT_ARMORY_ROOT) -> list[ArmoryEntry]:
    d = root / "extensions"
    if not d.exists():
        return []
    out: list[ArmoryEntry] = []
    for child in sorted(d.iterdir()):
        mf = child / "extension.json"
        if mf.exists():
            e = _parse_manifest(mf, "extension")
            if e:
                out.append(e)
    return out


def find_alias(command_name: str, root: Path = DEFAULT_ARMORY_ROOT) -> Optional[ArmoryEntry]:
    for e in scan_aliases(root):
        if e.command_name == command_name or e.name == command_name:
            return e
    return None


def find_extension(command_name: str, root: Path = DEFAULT_ARMORY_ROOT) -> Optional[ArmoryEntry]:
    for e in scan_extensions(root):
        if e.command_name == command_name or e.name == command_name:
            return e
    return None


# ---------------------------------------------------------------------------
# BOF argument packer (subset)
# ---------------------------------------------------------------------------
# Sliver BOFs use a binary argument format with a 4-byte little-endian length
# prefix per arg, and per-type encoding:
#   int32   → 4 bytes little-endian
#   short   → 2 bytes little-endian
#   string  → UTF-8 bytes + NUL
#   wstring → UTF-16LE bytes + \x00\x00
#   file    → raw bytes (caller supplies)
# Ref: sliverarmory/sliver client/command/extensions/arguments.go

_SUPPORTED_BOF_TYPES = {"int", "int32", "short", "string", "wstring", "file"}


def pack_bof_args(spec: list[dict[str, Any]], values: list[Any]) -> bytes:
    """Pack typed args for a BOF call (inner BOFArgsBuffer stream).

    Mirrors Sliver's client/core/bof.go BOFArgsBuffer encoding per-arg:
      int/int32 → 4B LE (raw, no length prefix)
      short     → 2B LE (raw, no length prefix)
      string    → [u32 len=strlen+1][bytes][0x00]
      wstring   → [u32 len_bytes][utf16le bytes][0x00 0x00]
      file      → [u32 len][bytes]

    `spec`: manifest arguments list; `values`: Python values in spec order.
    None in values skips an optional arg.
    """
    out = bytearray()
    for i, item in enumerate(spec):
        typ = (item.get("type") or "string").lower()
        optional = item.get("optional", False)
        if i >= len(values) or values[i] is None:
            if optional:
                continue
            raise ValueError(f"Missing required arg: {item.get('name')}")
        val = values[i]
        if typ in ("int", "int32", "integer"):
            out += struct.pack("<I", int(val) & 0xFFFFFFFF)
        elif typ == "short":
            out += struct.pack("<H", int(val) & 0xFFFF)
        elif typ == "string":
            s = val if isinstance(val, bytes) else str(val).encode("utf-8")
            payload = s + b"\x00"
            out += struct.pack("<I", len(payload)) + payload
        elif typ == "wstring":
            s = str(val) + "\x00"
            utf16 = s.encode("utf-16-le")
            out += struct.pack("<I", len(utf16)) + utf16
        elif typ == "file":
            blob = bytes(val)
            out += struct.pack("<I", len(blob)) + blob
        else:
            raise ValueError(f"Unsupported BOF arg type: {typ}")
    return bytes(out)


def pack_bof_envelope(bof_entrypoint: str, bof_binary: bytes, packed_args: bytes) -> bytes:
    """Pack the outer envelope the coff-loader expects in CallExtension.Args.

    Matches Sliver CLI getBOFArgs() + BOFArgsBuffer.GetBuffer():
      inner = AddString(entrypoint) ++ AddData(bof_binary) ++ AddData(packed_args)
      outer = [u32 len(inner)] ++ inner
    """
    inner = bytearray()
    ep_bytes = bof_entrypoint.encode("utf-8") + b"\x00"
    inner += struct.pack("<I", len(ep_bytes)) + ep_bytes           # AddString
    inner += struct.pack("<I", len(bof_binary)) + bof_binary        # AddData
    inner += struct.pack("<I", len(packed_args)) + packed_args      # AddData
    return struct.pack("<I", len(inner)) + bytes(inner)


def sha256_hex(data: bytes) -> str:
    """SHA-256 hex digest of bytes (used as Extension Name on RegisterExtension/CallExtension)."""
    return hashlib.sha256(data).hexdigest()
