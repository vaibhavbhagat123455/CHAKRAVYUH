"""Small MCP-over-stdio client used by the dashboard and integration tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any


class StdioMcpClient:
    """Keep one proxy subprocess alive so HOLD state remains isolated and scoped."""

    def __init__(self, *, log_path: str | Path, approval_secret: str) -> None:
        env = os.environ.copy()
        env["LOG_PATH"] = str(log_path)
        env["APPROVAL_BRIDGE_SECRET"] = approval_secret
        self._process = subprocess.Popen(
            [sys.executable, "-m", "proxy.mcp_server"],
            cwd=str(Path(__file__).resolve().parents[1]),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=env,
        )
        self._lock = threading.Lock()
        self._next_id = 1

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if self._process.poll() is not None:
            stderr = self._process.stderr.read() if self._process.stderr else ""
            raise RuntimeError(f"MCP proxy exited unexpectedly: {stderr[-500:]}")
        with self._lock:
            request_id = self._next_id
            self._next_id += 1
            payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            assert self._process.stdin is not None and self._process.stdout is not None
            self._process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._process.stdin.flush()
            line = self._process.stdout.readline()
        if not line:
            raise RuntimeError("MCP proxy returned no JSON-RPC response")
        response = json.loads(line)
        if not isinstance(response, dict):
            raise RuntimeError("MCP proxy returned an invalid JSON-RPC response")
        return response

    def call_tool(self, request: dict[str, Any], content: str) -> dict[str, Any]:
        return self.call("tools/call", {"request": request, "content": content})

    def approve(self, request: dict[str, Any], approval_id: str, release_token: str) -> dict[str, Any]:
        return self.call("tools/approve", {"request": request, "request_id": request["request_id"],
                                            "approval_id": approval_id, "release_token": release_token})

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2)

    def __enter__(self) -> "StdioMcpClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


__all__ = ["StdioMcpClient"]
