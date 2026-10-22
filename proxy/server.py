"""MCP Proxy Server implementation with dependency injection and audit logging."""

from __future__ import annotations

from typing import Any, Dict, Optional

from proxy.config import ProxyConfig
from proxy.events import REQUEST_RECEIVED, emit
from proxy.interfaces import (
    Analyser,
    ApprovalService,
    Clock,
    LogWriter,
    ToolExecutor,
)
from proxy.models import ToolRequest


class ProxyServer:
    """Core MCP security proxy server intercepting and governing tool calls."""

    def __init__(
        self,
        log: LogWriter,
        analyser: Analyser,
        executor: ToolExecutor,
        approval: Optional[ApprovalService] = None,
        config: Optional[ProxyConfig] = None,
        clock: Optional[Clock] = None,
    ) -> None:
        self.log = log
        self.analyser = analyser
        self.executor = executor
        self.approval = approval
        self.config = config if config is not None else ProxyConfig()
        self.clock = clock

    def handle_tool_call(self, request: ToolRequest) -> Dict[str, Any]:
        """Handle incoming tool call attempt, logging initial receipt."""
        emit(self.log, REQUEST_RECEIVED, request.request_id, request.to_dict())
        return {"status": "received", "request_id": request.request_id}
