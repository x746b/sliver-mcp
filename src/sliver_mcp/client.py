"""Sliver client lifespan and target resolution helpers."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Literal

from sliver import SliverClient, SliverClientConfig

TargetKind = Literal["session", "beacon"]


@dataclass
class SliverCtx:
    client: SliverClient
    operator_config_path: str

    async def resolve(self, *, session_id: str | None = None, beacon_id: str | None = None):
        """Return an InteractiveSession or InteractiveBeacon for the given id.

        Caller must pass exactly one of session_id / beacon_id.
        """
        if (session_id is None) == (beacon_id is None):
            raise ValueError("Pass exactly one of session_id or beacon_id")
        if session_id:
            interact = await self.client.interact_session(session_id)
            if interact is None:
                raise LookupError(f"session not found: {session_id}")
            return interact, "session"
        interact = await self.client.interact_beacon(beacon_id)  # type: ignore[arg-type]
        if interact is None:
            raise LookupError(f"beacon not found: {beacon_id}")
        return interact, "beacon"

    async def wait_beacon_task(self, task_id: str, timeout: float = 60.0) -> dict[str, Any]:
        """Poll beacon_task_content until it returns completed task data or timeout."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                result = await self.client.beacon_task_content(task_id)
                if result and getattr(result, "State", "").lower() in ("completed", "failed", "canceled"):
                    return {"task_id": task_id, "state": result.State, "response": result}
            except Exception:
                pass
            await asyncio.sleep(2.0)
        return {"task_id": task_id, "state": "timeout", "response": None}


async def _connect(operator_config_path: str) -> SliverClient:
    cfg = SliverClientConfig.parse_config_file(operator_config_path)
    client = SliverClient(cfg)
    await client.connect()
    return client


@asynccontextmanager
async def sliver_lifespan(operator_config_path: str):
    client = await _connect(operator_config_path)
    try:
        yield SliverCtx(client=client, operator_config_path=operator_config_path)
    finally:
        close = getattr(client, "close", None)
        if close:
            try:
                result = close()
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                pass
