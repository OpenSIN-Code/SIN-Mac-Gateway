from __future__ import annotations

import asyncio
import itertools
import json
from collections.abc import Awaitable
from typing import Any


class BackendError(RuntimeError):
    pass


class StdioMCPBackend:
    """Concurrent JSON-RPC client for the existing stdio mcp-combiner."""

    def __init__(self, command: list[str]) -> None:
        self.command = command
        self.process: asyncio.subprocess.Process | None = None
        self._ids = itertools.count(1)
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._write_lock = asyncio.Lock()
        self._start_lock = asyncio.Lock()
        self._initialized = False

    async def start(self) -> None:
        async with self._start_lock:
            if self.process and self.process.returncode is None and self._initialized:
                return
            self.process = await asyncio.create_subprocess_exec(
                *self.command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=None,
            )
            self._reader_task = asyncio.create_task(self._reader_loop())
            response = await self._request_raw(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "SIN Mac Gateway", "version": "0.2.0"},
                },
                timeout=30.0,
            )
            if "error" in response:
                raise BackendError(str(response["error"]))
            await self.notify("notifications/initialized", {})
            self._initialized = True

    async def _reader_loop(self) -> None:
        assert self.process and self.process.stdout
        try:
            while True:
                line = await self.process.stdout.readline()
                if not line:
                    break
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                request_id = message.get("id")
                if isinstance(request_id, int):
                    future = self._pending.pop(request_id, None)
                    if future and not future.done():
                        future.set_result(message)
        finally:
            error = BackendError("local mcp-combiner closed")
            for future in list(self._pending.values()):
                if not future.done():
                    future.set_exception(error)
            self._pending.clear()
            self._initialized = False

    async def _send(self, payload: dict[str, Any]) -> None:
        if not self.process or self.process.returncode is not None or not self.process.stdin:
            raise BackendError("local mcp-combiner is not running")
        async with self._write_lock:
            self.process.stdin.write((json.dumps(payload, separators=(",", ":")) + "\n").encode())
            await self.process.stdin.drain()

    async def _request_raw(
        self,
        method: str,
        params: dict[str, Any],
        *,
        timeout: float | None,
    ) -> dict[str, Any]:
        request_id = next(self._ids)
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            await self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            if timeout is None:
                return await future
            return await asyncio.wait_for(future, timeout)
        except Exception:
            self._pending.pop(request_id, None)
            raise

    async def request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        await self.start()
        response = await self._request_raw(method, params, timeout=timeout)
        if "error" in response:
            raise BackendError(str(response["error"]))
        result = response.get("result")
        if not isinstance(result, dict):
            raise BackendError(f"invalid backend response for {method}")
        return result

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        await self._send({"jsonrpc": "2.0", "method": method, "params": params})

    async def list_tools(self) -> list[dict[str, Any]]:
        result = await self.request("tools/list", {}, timeout=30.0)
        tools = result.get("tools", [])
        if not isinstance(tools, list):
            raise BackendError("backend tools/list returned a non-list")
        return [tool for tool in tools if isinstance(tool, dict)]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return await self.request(
            "tools/call",
            {"name": name, "arguments": arguments},
            timeout=None,
        )

    async def close(self) -> None:
        process = self.process
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 3.0)
            except TimeoutError:
                process.kill()
                await process.wait()
        if self._reader_task:
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        self.process = None
        self._initialized = False
