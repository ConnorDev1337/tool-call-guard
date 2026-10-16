"""MCP stdio proxy: ``client <-> toolguard <-> server``.

Replace a server's command in any MCP client configuration with::

    toolguard mcp-proxy --server-name gmail --session my-agent -- npx -y some-gmail-mcp

The proxy relays JSON-RPC lines unchanged except for ``tools/call``:

* the call is evaluated as ``mcp__<server-name>__<tool>`` (Claude Code naming,
  so the presets apply to any client);
* ALLOW -> forwarded; its result is recorded if the tool is a policy source;
* BLOCK -> answered by the proxy with an ``isError`` tool result that explains
  why, so the model learns the call was refused;
* CONFIRM -> if the client supports *elicitation*, the user is asked through
  the client UI (the model cannot answer an elicitation); otherwise the
  request is queued and a human approves it with ``toolguard approve <id>``,
  after which the identical call can be retried.

Several proxies (one per server) share taint through the same ``--session``
and state directory, so data read through one server is tracked when it
reaches another.
"""

from __future__ import annotations

import contextlib
import itertools
import json
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import IO, Any

from ..approvals import ApprovalRequest, QueueApprover
from ..guard import Guard
from ..model import Action, Decision
from ..redact import redact_args

ELICITATION_TIMEOUT = 300.0


class McpProxy:
    def __init__(
        self,
        guard: Guard,
        server_name: str,
        command: list[str],
        *,
        client_in: IO[bytes] | None = None,
        client_out: IO[bytes] | None = None,
        elicitation_timeout: float = ELICITATION_TIMEOUT,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    ) -> None:
        self.guard = guard
        self.server_name = server_name
        self.command = command
        self.client_in = client_in or sys.stdin.buffer
        self.client_out = client_out or sys.stdout.buffer
        self.elicitation_timeout = elicitation_timeout
        self.popen = popen
        self.queue = QueueApprover(guard.store, clock=guard.clock)
        self.client_elicitation = False
        self._out_lock = threading.Lock()
        self._in_lock = threading.Lock()
        self._calls: dict[Any, tuple[str, Any]] = {}
        self._calls_lock = threading.Lock()
        self._waiters: dict[str, tuple[threading.Event, list[dict[str, Any]]]] = {}
        self._ids = itertools.count(1)
        self.server: subprocess.Popen[bytes] | None = None

    # ------------------------------------------------------------------ I/O

    def _send_client(self, message: dict[str, Any]) -> None:
        data = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        with self._out_lock:
            self.client_out.write(data)
            self.client_out.flush()

    def _send_server_raw(self, line: bytes) -> None:
        assert self.server is not None and self.server.stdin is not None  # noqa: S101
        with self._in_lock:
            try:
                self.server.stdin.write(line if line.endswith(b"\n") else line + b"\n")
                self.server.stdin.flush()
            except OSError:
                pass  # server gone; its exit ends the proxy

    def _send_server(self, message: dict[str, Any]) -> None:
        self._send_server_raw(json.dumps(message, ensure_ascii=False).encode("utf-8"))

    # ------------------------------------------------------------------ main loop

    def run(self) -> int:
        self.server = self.popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        threading.Thread(target=self._pump_server, daemon=True).start()
        threading.Thread(target=self._pump_client, daemon=True).start()
        return self.server.wait()

    def _pump_client(self) -> None:
        for line in self.client_in:
            if line.strip():
                self.handle_client_line(line)
        if self.server and self.server.stdin:
            with self._in_lock, contextlib.suppress(OSError):
                self.server.stdin.close()

    def _pump_server(self) -> None:
        assert self.server is not None and self.server.stdout is not None  # noqa: S101
        for line in self.server.stdout:
            if line.strip():
                self.handle_server_line(line)

    # ------------------------------------------------------------------ client -> server

    def handle_client_line(self, line: bytes) -> None:
        try:
            message = json.loads(line)
        except ValueError:
            self._send_server_raw(line)
            return
        if not isinstance(message, dict):
            self._send_server_raw(line)
            return
        if "method" not in message and str(message.get("id", "")).startswith("toolguard-"):
            self._resolve_elicitation(message)
            return
        method = message.get("method")
        if method == "initialize":
            capabilities = (message.get("params") or {}).get("capabilities") or {}
            self.client_elicitation = "elicitation" in capabilities
        if method == "tools/call" and "id" in message:
            self._guard_call(message)
            return
        self._send_server_raw(line)

    def _tool_name(self, message: dict[str, Any]) -> tuple[str, Any]:
        params = message.get("params") or {}
        name = str(params.get("name", ""))
        return f"mcp__{self.server_name}__{name}", params.get("arguments") or {}

    def _guard_call(self, message: dict[str, Any]) -> None:
        tool, args = self._tool_name(message)
        decision = self.guard.evaluate(tool, args)
        if decision.mode == "monitor" or decision.action == Action.ALLOW:
            decision.effective = Action.ALLOW
            self._audit(decision)
            self._forward_call(message, tool, args)
        elif decision.action == Action.BLOCK:
            self._audit(decision)
            self._refuse(message, decision)
        elif self.client_elicitation:
            threading.Thread(
                target=self._confirm_via_elicitation,
                args=(message, tool, args, decision),
                daemon=True,
            ).start()
        else:
            self._confirm_via_queue(message, tool, args, decision)

    def _forward_call(self, message: dict[str, Any], tool: str, args: Any) -> None:
        with self._calls_lock:
            self._calls[message["id"]] = (tool, args)
        self._send_server(message)

    def _refuse(self, message: dict[str, Any], decision: Decision) -> None:
        self._send_client(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": decision.explain()}],
                    "isError": True,
                },
            }
        )

    def _audit(self, decision: Decision) -> None:
        record = self.guard.decision_record(decision)
        record.update(integration="mcp-proxy", server=self.server_name)
        self.guard.audit.append("decision", self.guard.session, record)

    def _confirm_via_queue(
        self, message: dict[str, Any], tool: str, args: Any, decision: Decision
    ) -> None:
        outcome = self.queue.request(
            ApprovalRequest(
                session=self.guard.session,
                tool=tool,
                fingerprint=decision.fingerprint,
                summary=decision.explain(),
                args_preview=redact_args(args, 200),
            )
        )
        decision.approval_status = outcome.status
        decision.approval_id = outcome.approval_id
        decision.approved_by = outcome.by
        decision.effective = Action.ALLOW if outcome.status == "approved" else Action.BLOCK
        self._audit(decision)
        if decision.effective == Action.ALLOW:
            self._forward_call(message, tool, args)
        else:
            self._refuse(message, decision)

    def _confirm_via_elicitation(
        self, message: dict[str, Any], tool: str, args: Any, decision: Decision
    ) -> None:
        request_id = f"toolguard-{next(self._ids)}"
        event: threading.Event = threading.Event()
        box: list[dict[str, Any]] = []
        self._waiters[request_id] = (event, box)
        self._send_client(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "elicitation/create",
                "params": {
                    "message": decision.explain()
                    + f"\n\nArguments (redacted): {json.dumps(redact_args(args, 200))}",
                    "requestedSchema": {
                        "type": "object",
                        "properties": {
                            "approve": {
                                "type": "boolean",
                                "title": f"Allow {tool}?",
                                "description": "Approve this single tool call",
                            }
                        },
                        "required": ["approve"],
                    },
                },
            }
        )
        answered = event.wait(self.elicitation_timeout)
        self._waiters.pop(request_id, None)
        response = box[0] if box else {}
        result = response.get("result") or {}
        approved = (
            answered
            and result.get("action") == "accept"
            and (result.get("content") or {}).get("approve") is True
        )
        decision.approval_status = "approved" if approved else "denied"
        decision.approved_by = "mcp-elicitation" if answered else None
        if not answered:
            decision.approval_status = "denied"
        decision.effective = Action.ALLOW if approved else Action.BLOCK
        self._audit(decision)
        if approved:
            self._forward_call(message, tool, args)
        else:
            self._refuse(message, decision)

    def _resolve_elicitation(self, message: dict[str, Any]) -> None:
        waiter = self._waiters.get(str(message.get("id")))
        if waiter is not None:
            event, box = waiter
            box.append(message)
            event.set()

    # ------------------------------------------------------------------ server -> client

    def handle_server_line(self, line: bytes) -> None:
        try:
            message = json.loads(line)
        except ValueError:
            message = None
        if isinstance(message, dict) and "id" in message and "method" not in message:
            with self._calls_lock:
                call = self._calls.pop(message["id"], None)
            if call is not None and isinstance(message.get("result"), dict):
                tool, args = call
                result = message["result"]
                payload = {k: result.get(k) for k in ("content", "structuredContent")}
                self.guard.observe(tool, payload, args)
        with self._out_lock:
            self.client_out.write(line if line.endswith(b"\n") else line + b"\n")
            self.client_out.flush()
