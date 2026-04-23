# sliver-mcp

Python MCP server for the [Sliver C2](https://github.com/BishopFox/sliver) adversary-emulation framework. Exposes ~74 tools covering exec, armory (aliases + BOF extensions), listeners, implant generation, identity, recon, registry, services, websites, and intel (hosts/loot/canaries).

Designed to **complement** the official `sliver-client mcp` which ships with Sliver v1.7+ but covers only filesystem tools. Use both side-by-side.

## Related 

- **[EDR-Resilient Windows Payload Loader](https://github.com/x746b/shellcodes/tree/main/loader)** - A modular, multi-layer evasion loader for delivering e.g. Sliver beacon shellcode onto modern Windows targets with Microsoft Defender / EDR enabled. Cross-compiles from Kali Linux (MinGW-w64) or builds natively with VS2022.


## Scope

| Area | This MCP (`sliver-mcp`) | Official (`sliver-client mcp`) |
|------|-----|-----|
| Filesystem (ls/cat/cd/rm/...) | — |  10 tools |
| Exec (cmd, PS, shell, binary) |  4 tools | — |
| Shellcode / Assembly / Sideload / DLL |  4 tools | — |
| Upload / Download (binary-safe base64) |  2 tools | fs_cat text only |
| Listeners (mtls/http/https/dns/wg + stagers) |  6 tools | — |
| Implant generate / regenerate / builds / profiles |  7 tools | — |
| Sessions & beacons lifecycle |  11 tools |  list only |
| Identity (getsystem/impersonate/runas/maketoken) |  5 tools | — |
| Recon (ps/netstat/ifconfig/screenshot/procdump/ping) |  6 tools | — |
| Environment + Registry |  6 tools | — |
| **Armory aliases** (.NET assemblies: Rubeus, Seatbelt, SharpHound…) |  | — |
| **Armory BOFs** via coff-loader (sa-*, c2tc-*, bof-*…) |  | — |
| Intel (hosts/loot/canaries) |  4 tools | — |
| Websites |  4 tools | — |

## Requirements

- Python ≥ 3.11
- [`uv`](https://github.com/astral-sh/uv)
- A running Sliver server
- An operator `.cfg` (`sliver-server operator --name <you> --lhost <ip>`)

## Install

```bash
cd /opt
git clone <repo> sliver-mcp
cd sliver-mcp
uv venv
uv pip install -e .
```

## Run standalone

```bash
uv run sliver-mcp --operator-config ~/.sliver-client/configs/<op>.cfg
# or via env var:
SLIVER_OPERATOR_CONFIG=~/.sliver-client/configs/<op>.cfg uv run sliver-mcp
```

## MCP client configuration

### Claude Code / Claude Desktop

```json
{
  "mcpServers": {
    "sliver-mcp": {
      "type": "stdio",
      "command": "/opt/sliver-mcp/.venv/bin/sliver-mcp",
      "args": [
        "--operator-config",
        "/home/you/.sliver-client/configs/you_localhost.cfg"
      ]
    },
    "sliver-mcp-fs": {
      "type": "stdio",
      "command": "sliver-client",
      "args": [
        "mcp",
        "--config",
        "/home/you/.sliver-client/configs/you_localhost.cfg"
      ]
    }
  }
}
```

### Codex CLI (`~/.codex/config.toml`)

```toml
[mcp_servers.sliver-mcp]
command = "/opt/sliver-mcp/.venv/bin/sliver-mcp"
args = ["--operator-config", "/home/you/.sliver-client/configs/you_localhost.cfg"]

[mcp_servers.sliver-mcp-fs]
command = "sliver-client"
args = ["mcp", "--config", "/home/you/.sliver-client/configs/you_localhost.cfg"]
```

## Usage patterns

### Target addressing

All interactive tools take:
- `target_kind`: `"session"` | `"beacon"`
- `target_id`: UUID from `list_sessions` / `list_beacons`

Sessions execute synchronously; beacons queue tasks and return `task_id` immediately. Poll with `get_beacon_task_result(task_id, wait=true, timeout_seconds=60)`.

### Execution

```
exec_cmd         target_kind, target_id, command
exec_powershell  target_kind, target_id, command
exec_shell       target_kind, target_id, command
exec_binary      target_kind, target_id, exe, args[], output
exec_shellcode   target_kind, target_id, shellcode_base64, pid, rwx, encoder
exec_assembly    target_kind, target_id, assembly_base64, arguments, process, arch, ...
exec_sideload    target_kind, target_id, data_base64, process_name, arguments, ...
exec_spawn_dll   target_kind, target_id, data_base64, process_name, arguments, ...
```

### Armory — aliases (.NET assemblies)

```json
// CLI equivalent: rubeus -- triage
{
  "name": "armory_run_alias",
  "arguments": {
    "target_kind": "session",
    "target_id": "<sid>",
    "command_name": "rubeus",
    "arguments": "triage",
    "process": "notepad.exe"
  }
}
```

Auto-resolves the architecture, picks the matching `.exe`, runs via `execute_assembly` with the correct bitness (`x64`/`x86`).

### Armory — BOF extensions (sa-*, c2tc-*, bof-*)

```json
// CLI equivalent: sa-cacls -- -filepath "C:\\Windows\\temp"
{
  "name": "armory_run_extension",
  "arguments": {
    "target_kind": "session",
    "target_id": "<sid>",
    "command_name": "sa-cacls",
    "arguments": {"filepath": "C:\\Windows\\temp"}
  }
}
```

`arguments` accepts **either** form:

| CLI | List (positional) | Dict (flag-style, recommended) |
|-----|-------------------|--------------------------------|
| `sa-cacls -- -filepath C:\Windows\temp` | `["C:\\Windows\\temp"]` | `{"filepath": "C:\\Windows\\temp"}` |
| `sa-netshares -- -computername DC01 -as-admin 1` | `["DC01", 1]` | `{"computername": "DC01", "as-admin": 1}` |
| `sa-netshares -- -as-admin 1` | `[null, 1]` | `{"as-admin": 1}` |

Dict form mirrors Sliver CLI flag syntax and handles skipped optional args automatically — missing keys get packed with defaults (`""` for wstring, `0` for int) matching [Sliver's argparser](https://github.com/BishopFox/sliver/blob/master/client/command/extensions/argparser.go).

### Under the hood — BOF execution

BOFs (`.o` COFF objects) don't register directly. `armory_run_extension` mirrors `client/command/extensions/load.go`:

1. Resolve `depends_on` chain (usually `coff-loader`).
2. `RegisterExtension` the dep's PE (`.dll`) with `Name = sha256(binary_bytes)` hex.
3. Pack typed args per manifest (int/short/string/wstring/file) into a buffer matching `BOFArgsBuffer`.
4. Build the outer envelope: `[u32 total_len] [AddString(bof_entrypoint)] [AddData(bof_bytes)] [AddData(packed_args)]`.
5. `CallExtension` with `Name = sha256(dep_binary)`, `Export = dep.entrypoint` (usually `LoadAndRun`), `Args = envelope`.

Output from the BOF surfaces in `call.Output` as decoded UTF-8 text (bytes are auto-decoded for common text fields).

### Intel

```
list_hosts     — raw Hosts RPC
list_loot      — raw LootAll RPC
loot_content   — LootContent by ID (binary returned as base64 in File.data_base64)
list_canaries  — DNS canaries on implants
```

These use raw `SliverClient._stub.<Method>` calls since sliver-py v0.0.19 doesn't wrap them yet.

## Architecture

```
src/sliver_mcp/
├── server.py         # FastMCP bootstrap + all tool definitions (~1000 LOC)
├── client.py         # SliverClient lifespan, target resolver (session|beacon),
│                     #   beacon task polling
├── armory.py         # Armory manifest scanner, BOF arg packer (BOFArgsBuffer port),
│                     #   BOF envelope packer (coff-loader framing), sha256 naming
└── serializers.py    # protobuf → dict (MessageToDict), base64 helpers,
                      #   text-byte auto-decoder (Stdout/Stderr/Output/Response)
```

- Single persistent `SliverClient` over the MCP process lifetime (one mTLS handshake at startup).
- Protobuf responses → dict via `MessageToDict(preserving_proto_field_name=True)`.
- Binary fields (shellcode, assembly bytes, BOF data, screenshots, process dumps) are base64 on the MCP wire.
- Text fields (`Stdout`/`Stderr`/`Output`/`Response`) auto-decoded to UTF-8 strings.

## Known limitations / gotchas

- **BOFs are not re-entrant** in a single implant process. Run `armory_run_extension` calls sequentially per target. Parallel calls can destabilize the implant (observed in the wild).
- **Defender-on targets**: Rubeus, SharpHound, heavy .NET tooling can trip AMSI mid-load. Use lighter BOFs (sa-*) or switch to beacons for less temporal signal.
- **Some BOFs self-reference fails**: e.g. `sa-netshares -computername DC01` on DC01 itself returns Windows error 53 (`ERROR_BAD_NETPATH`) — a BOF/OS limitation, not MCP.
- **Large outputs**: `armory_list_extensions` returns ~27KB for ~150 extensions. Use `armory_extension_info <name>` for full manifest details instead of scanning everything.
- **No armory install** — `sliver armory install <pkg>` runs through Sliver's CLI package manager which we don't re-implement. Install via the Sliver console; this MCP only consumes the already-installed armory at `~/.sliver-client/{aliases,extensions}/`.
- **No event stream ring buffer** — `client.events()` exists but isn't wired to a background consumer yet.
- **No audit log / allowlist / read-only mode** — planned.

## Versions

| Tag | Change |
|-----|--------|
| 0.1.0 | 61 tools: exec, listeners, implants, identity, recon, registry, websites |
| 0.2.0 | +13 tools: armory (aliases + BOFs via coff-loader) + intel (hosts/loot/canaries); raw gRPC fallback for what sliver-py doesn't expose |
| 0.2.1 | Trimmed armory list summaries (78KB→27KB extensions, 18KB→4.4KB aliases) |
| 0.2.2 | `armory_run_extension.arguments` accepts dict (flag-style) in addition to list (positional) |
| 0.2.3 | Pack defaults for missing optional BOF args (matches Sliver CLI `argparser.go`) |

## References

- [BishopFox/sliver](https://github.com/BishopFox/sliver) — Sliver C2
- [moloch--/sliver-py](https://github.com/moloch--/sliver-py) — Python gRPC client (GPL-3.0)
- [mcp-python-sdk](https://github.com/modelcontextprotocol/python-sdk) — MCP SDK
- Sliver extension loader: [`client/command/extensions/load.go`](https://github.com/BishopFox/sliver/blob/master/client/command/extensions/load.go)
- BOF arg buffer: [`client/core/bof.go`](https://github.com/BishopFox/sliver/blob/master/client/core/bof.go)

## Authorization

This MCP is intended strictly for **authorized offensive security work** (commercial pentests, HackTheBox / VulnLab / RedTeam Labs, sanctioned red team engagements). The operator config grants full Sliver server access — protect it accordingly. All operator actions are logged server-side by Sliver.

## License

MIT
