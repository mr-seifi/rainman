"""Model Context Protocol server over the agent tools.

MCP is JSON-RPC 2.0. This implements the slice an agent needs — ``initialize``,
``ping``, ``tools/list``, ``tools/call`` — with no dependency, over two
transports that share ``handle``:

- **stdio** (``rainman mcp``): one JSON message per line on stdin/stdout.
- **HTTP** (``POST /mcp`` on ``rainman serve``): one JSON-RPC message or batch
  per request, answered as plain JSON (stateless streamable HTTP).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Optional, TextIO

from .tools import INSTRUCTIONS, AgentTools, ToolError

SUPPORTED_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
SERVER_INFO = {"name": "rainman", "title": "rainman recon graph", "version": "0.1.0"}

_PARSE_ERROR, _INVALID_REQUEST, _METHOD_NOT_FOUND, _INVALID_PARAMS, _INTERNAL = (
    -32700, -32600, -32601, -32602, -32603)


def _error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _text(payload: Any, *, is_error: bool = False) -> dict:
    text = payload if isinstance(payload, str) else json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), default=str)
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


class McpServer:
    def __init__(self, tools: AgentTools) -> None:
        self.tools = tools

    def handle(self, msg: Any) -> Optional[dict]:
        """One JSON-RPC message in, its response out (None for notifications)."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
            if isinstance(msg, dict) and ("result" in msg or "error" in msg):
                return None                 # a response to us; we never send requests
            return _error(msg.get("id") if isinstance(msg, dict) else None,
                          _INVALID_REQUEST, "not a JSON-RPC 2.0 request")
        method, req_id = msg["method"], msg.get("id")
        params = msg.get("params") or {}
        if "id" not in msg:
            return None                     # notification (initialized, cancelled, …)
        if not isinstance(params, dict):
            return _error(req_id, _INVALID_PARAMS, "params must be an object")
        try:
            result = self._dispatch(method, params)
        except LookupError:
            return _error(req_id, _METHOD_NOT_FOUND, f"method {method!r} is not supported")
        except Exception as e:              # never let one bad call end the session
            return _error(req_id, _INTERNAL, f"{type(e).__name__}: {e}")
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _dispatch(self, method: str, params: dict) -> dict:
        if method == "initialize":
            wanted = params.get("protocolVersion")
            return {
                "protocolVersion": wanted if wanted in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": INSTRUCTIONS,
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": self.tools.specs()}
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(name, str) or not isinstance(arguments, dict):
                return _text("tools/call needs a tool name and an arguments object", is_error=True)
            try:
                return _text(self.tools.call(name, arguments))
            except ToolError as e:
                # a tool-level error the model can read and correct, not a protocol fault
                return _text(str(e), is_error=True)
            except TypeError as e:
                return _text(f"bad arguments for {name}: {e}", is_error=True)
        # clients probe these even when the capability is not advertised
        if method == "resources/list":
            return {"resources": []}
        if method == "resources/templates/list":
            return {"resourceTemplates": []}
        if method == "prompts/list":
            return {"prompts": []}
        raise LookupError(method)

    def handle_payload(self, payload: Any) -> Any:
        """A decoded HTTP body: a single message or a batch. Returns the JSON to
        send back, or None when nothing is owed (only notifications)."""
        if isinstance(payload, list):
            if not payload:
                return _error(None, _INVALID_REQUEST, "empty batch")
            out = [r for r in (self.handle(m) for m in payload) if r is not None]
            return out or None
        return self.handle(payload)

    def serve_stdio(self, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as e:
                reply: Any = _error(None, _PARSE_ERROR, f"invalid JSON: {e}")
            else:
                reply = self.handle_payload(payload)
            if reply is not None:
                stdout.write(json.dumps(reply, ensure_ascii=False, default=str) + "\n")
                stdout.flush()
