# sliver-mcp

MCP server for the Sliver C2 framework. Complements the official `sliver-client mcp` (fs-only, 11 tools) with **everything else**: exec, armory/extensions, implants, listeners, identity, recon, registry, services, websites.

Written in Python on top of [`sliver-py`](https://github.com/moloch--/sliver-py).

## Scope

This MCP deliberately **skips filesystem tools** (`fs_ls`, `fs_cat`, etc.) because the official Sliver MCP covers them natively. Use both servers side by side:

- `sliver-client mcp` → filesystem recon
- `sliver-mcp` → everything else

## Requirements

- Python ≥3.11, `uv`
- Running Sliver server
- Sliver operator config (generated via `new-operator` in Sliver console)

## Install

```bash
cd /opt/sliver-mcp
uv venv
uv pip install -e .
```

## Run

```bash
uv run sliver-mcp --operator-config ~/.sliver-client/configs/xtk_localhost.cfg
```

## MCP client config (Claude Code / Codex)

```json
{
  "mcpServers": {
    "sliver-mcp": {
      "command": "uv",
      "args": [
        "--directory", "/opt/sliver-mcp",
        "run", "sliver-mcp",
        "--operator-config", "/home/xtk/.sliver-client/configs/xtk_localhost.cfg"
      ]
    },
    "sliver-mcp-fs": {
      "command": "sliver-client",
      "args": ["mcp", "--config", "/home/xtk/.sliver-client/configs/xtk_localhost.cfg"]
    }
  }
}
```
