"""MCP stdio proxy that guards ``tools/call`` requests between a client and a server.

Calls are evaluated as ``mcp__<server-name>__<tool>`` (Claude Code naming), so the
presets apply to any client. Results that reach the model are observed as sources:
those of tools, and those of ``resources/read`` (including reads of resource
templates) and ``prompts/get``, under the names ``mcp__<server-name>__resources/read``
and ``mcp__<server-name>__prompts/get``, which no real tool can take (tool names
cannot contain ``/``). Confirmations use MCP elicitation when the client
supports it, since the model cannot answer an elicitation; otherwise they go to
the approval queue, whose one-time code reaches the human only through an
out-of-band notifier (never the error text the model reads). Proxies that share a
``--session`` and state directory share taint, so data read through one server is
tracked when it reaches another.

The proxy only forwards what it has inspected: client lines that are not JSON are
answered with a parse error instead of being relayed, batches are split and each
message is handled on its own, and a ``tools/call`` it cannot evaluate is refused.
"""

from __future__ import annotations

import contextlib
import json
import secrets
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import IO, Any

from ..approvals import ApprovalRequest, QueueApprover, apply_outcome
from ..guard import Guard
from ..model import Action, Decision
from ..redact import redact_args

ELICITATION_TIMEOUT = 300.0  # Seconds to wait for the user's answer
SHUTDOWN_GRACE = 5.0  # Seconds the server gets to exit at each step of the shutdown

# Request metadata that marks the stateless revision (2026-07-28), which has no initialize.
PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
INVALID_PARAMS = -32602

# Requests other than ``tools/call`` whose results reach the model: the parameters
# observed as the call's arguments and the result fields that carry the content.
OBSERVED_READS = {
    "resources/read": (("uri",), ("contents",)),
    "prompts/get": (("name", "arguments"), ("description", "messages")),
}
TOOL_RESULT_FIELDS = ("content", "structuredContent")


def _valid_id(value: Any) -> bool:
    """Return whether ``value`` is a usable JSON-RPC request id (string or integer)."""
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class _Pending:
    """A ``tools/call`` waiting for the user's confirmation."""

    def __init__(self) -> None:
        self.cancelled = threading.Event()
        self.elicitation: str | None = None


class McpProxy:
    """Relay JSON-RPC lines between a client and a server, guarding ``tools/call``.

    Blocked calls never reach the server: the proxy answers them with an
    ``isError`` result that explains the decision.
    """

    def __init__(
        self,
        guard: Guard,
        server_name: str,
        command: list[str],
        *,
        client_in: IO[bytes] | None = None,
        client_out: IO[bytes] | None = None,
        elicitation_timeout: float = ELICITATION_TIMEOUT,
        shutdown_grace: float = SHUTDOWN_GRACE,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        queue: QueueApprover | None = None,
    ) -> None:
        self.guard = guard
        self.server_name = server_name
        self.command = command
        self.client_in = client_in or sys.stdin.buffer
        self.client_out = client_out or sys.stdout.buffer
        self.elicitation_timeout = elicitation_timeout
        self.shutdown_grace = shutdown_grace
        self.popen = popen
        # Without configured notifiers the queue denies (fail closed).
        self.queue = queue or QueueApprover(guard.store, clock=guard.clock, audit=guard.audit)
        self.client_elicitation = False
        self._out_lock = threading.Lock()
        self._in_lock = threading.Lock()
        self._state_lock = threading.Lock()
        # Forwarded requests whose results are observed (``tools/call``, ``tasks/result``
        # and the reads in OBSERVED_READS) -> (tool, arguments, result fields).
        self._calls: dict[Any, tuple[str, Any, tuple[str, ...]]] = {}
        # Tasks created by a task-augmented ``tools/call`` -> (tool, arguments, fields).
        self._tasks: dict[str, tuple[str, Any, tuple[str, ...]]] = {}
        # Client request ids of calls waiting for a confirmation.
        self._pending: dict[Any, _Pending] = {}
        # Elicitations sent by the proxy: every id issued, and the ones still awaited.
        self._issued: set[str] = set()
        self._waiters: dict[str, tuple[threading.Event, list[dict[str, Any]]]] = {}
        self._client_gone = False
        self._stopping = False
        self.server: subprocess.Popen[bytes] | None = None

    # ------------------------------------------------------------------ I/O

    def _write_client(self, data: bytes) -> None:
        with self._out_lock:
            if self._client_gone:
                return
            try:
                self.client_out.write(data)
                self.client_out.flush()
            except (OSError, ValueError):
                # The client went away: nobody can read results, so stop the server.
                self._client_gone = True
                threading.Thread(target=self.stop_server, daemon=True).start()

    def _send_client(self, message: dict[str, Any]) -> None:
        self._write_client((json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8"))

    def _send_server_raw(self, line: bytes) -> None:
        if self.server is None or self.server.stdin is None:
            raise RuntimeError("the MCP server is not running")
        with self._in_lock:
            try:
                self.server.stdin.write(line if line.endswith(b"\n") else line + b"\n")
                self.server.stdin.flush()
            except (OSError, ValueError):
                pass  # Server gone; its exit ends the proxy

    def _send_server(self, message: Any) -> None:
        self._send_server_raw(json.dumps(message, ensure_ascii=False).encode("utf-8"))

    # ------------------------------------------------------------------ main loop

    def resolve_command(self) -> list[str]:
        """Return the server command with its program resolved on ``PATH``.

        On Windows this finds launchers such as ``npx.cmd`` that ``CreateProcess``
        does not look up by bare name.
        """
        command = list(self.command)
        if command:
            command[0] = shutil.which(command[0]) or command[0]
        return command

    def run(self) -> int:
        """Start the server, relay messages until it exits and return its exit code."""
        self.server = self.popen(
            self.resolve_command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )
        server_pump = threading.Thread(target=self._pump_server, daemon=True)
        server_pump.start()
        threading.Thread(target=self._pump_client, daemon=True).start()
        code = self.server.wait()
        server_pump.join(self.shutdown_grace)  # Relay what the server wrote before exiting
        return code

    def stop_server(self) -> None:
        """Close the server's stdin, then terminate and kill it if it does not exit.

        This is the stdio shutdown sequence of the MCP specification; without it a
        server that keeps timers running would outlive its client.
        """
        server = self.server
        with self._state_lock:
            if server is None or self._stopping:
                return
            self._stopping = True
        if server.stdin is not None:
            with self._in_lock, contextlib.suppress(OSError):
                server.stdin.close()
        for stop in (None, server.terminate, server.kill):
            if stop is not None:
                with contextlib.suppress(OSError):
                    stop()
            try:
                server.wait(self.shutdown_grace)
                return
            except subprocess.TimeoutExpired:
                continue

    def _pump_client(self) -> None:
        for line in self.client_in:
            if line.strip():
                self.handle_client_line(line)
        self.stop_server()

    def _pump_server(self) -> None:
        if self.server is None or self.server.stdout is None:
            raise RuntimeError("the MCP server is not running")
        for line in self.server.stdout:
            if line.strip():
                self.handle_server_line(line)

    # ------------------------------------------------------------------ client -> server

    def handle_client_line(self, line: bytes) -> None:
        """Guard each ``tools/call`` in a client line; relay other messages unchanged.

        A line that is not valid UTF-8 is decoded with replacement characters and
        forwarded as re-encoded JSON, so the server receives exactly what was guarded.
        """
        try:
            text = line.decode("utf-8")
            exact = True
        except UnicodeDecodeError:
            text = line.decode("utf-8", "replace")
            exact = False
        try:
            message = json.loads(text)
        except ValueError:
            # Never relay what could not be inspected: the server might parse it differently.
            self._send_client(_error(None, PARSE_ERROR, "Parse error"))
            return
        if isinstance(message, list):
            # A JSON-RPC batch (allowed before protocol 2025-06-18): handle each message.
            if not message:
                self._send_client(_error(None, INVALID_REQUEST, "Invalid Request"))
            for item in message:
                self._handle_client_message(item, None)
            return
        self._handle_client_message(message, line if exact else None)

    def _handle_client_message(self, message: Any, raw: bytes | None) -> None:
        if not isinstance(message, dict):
            self._send_client(_error(None, INVALID_REQUEST, "Invalid Request"))
            return
        method = message.get("method")
        if method is None and self._resolve_elicitation(message):
            return
        if method == "initialize":
            self._note_capabilities(message)
        elif method == "tools/call":
            self._guard_call(message)
            return
        elif method == "tasks/result":
            self._track_task_result(message)
        elif isinstance(method, str) and method in OBSERVED_READS:
            self._track_read(message, method)
        elif method == "notifications/cancelled" and self._cancel_pending(message):
            return
        if raw is not None:
            self._send_server_raw(raw)
        else:
            self._send_server(message)

    def _note_capabilities(self, message: dict[str, Any]) -> None:
        params = message.get("params")
        capabilities = params.get("capabilities") if isinstance(params, dict) else None
        elicitation = capabilities.get("elicitation") if isinstance(capabilities, dict) else None
        # An empty object means form mode, the only mode the proxy uses.
        self.client_elicitation = isinstance(elicitation, dict) and (
            not elicitation or "form" in elicitation
        )

    def _tool_name(self, message: dict[str, Any]) -> tuple[str, Any]:
        """Return the guarded tool name and the arguments of a ``tools/call`` request."""
        params = message.get("params")
        if not isinstance(params, dict):
            raise ValueError("params must be an object")
        name = params.get("name")
        args = params.get("arguments")
        if not isinstance(name, str) or not name:
            raise ValueError("params.name must be a non-empty string")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise ValueError("params.arguments must be an object")
        return f"mcp__{self.server_name}__{name}", args

    def _guard_call(self, message: dict[str, Any]) -> None:
        if "id" not in message:
            return  # A tools/call notification is invalid and has nobody to answer: drop it
        request_id = message["id"]
        if not _valid_id(request_id):
            self._send_client(_error(None, INVALID_REQUEST, "Invalid Request: bad id"))
            return
        try:
            tool, args = self._tool_name(message)
        except ValueError as exc:
            self._send_client(_error(request_id, INVALID_PARAMS, f"Invalid params: {exc}"))
            return
        decision = self.guard.evaluate(tool, args)
        if decision.mode == "monitor" or decision.action == Action.ALLOW:
            decision.effective = Action.ALLOW
            self._audit(decision)
            self._forward_call(message, tool, args)
        elif decision.action == Action.BLOCK:
            self._audit(decision)
            self._refuse(message, decision)
        elif self.client_elicitation:
            pending = _Pending()
            with self._state_lock:
                self._pending[request_id] = pending
            # Wait off the client pump, which must keep reading to receive the answer.
            threading.Thread(
                target=self._confirm_via_elicitation,
                args=(message, tool, args, decision, pending),
                daemon=True,
            ).start()
        else:
            self._confirm_via_queue(message, tool, args, decision)

    def _forward_call(self, message: dict[str, Any], tool: str, args: Any) -> None:
        with self._state_lock:
            self._calls[message["id"]] = (tool, args, TOOL_RESULT_FIELDS)
        self._send_server(message)

    def _track_read(self, message: dict[str, Any], method: str) -> None:
        """Remember a ``resources/read`` or ``prompts/get`` so its result is observed."""
        request_id = message.get("id")
        params = message.get("params")
        if not _valid_id(request_id) or not isinstance(params, dict):
            return  # The server answers it with an error, which is not observed
        names, fields = OBSERVED_READS[method]
        args = {name: params[name] for name in names if name in params}
        with self._state_lock:
            self._calls[request_id] = (f"mcp__{self.server_name}__{method}", args, fields)

    def _refuse(self, message: dict[str, Any], decision: Decision) -> None:
        result: dict[str, Any] = {
            "content": [{"type": "text", "text": decision.explain()}],
            "isError": True,
        }
        params = message.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        if isinstance(meta, dict) and PROTOCOL_VERSION_META in meta:
            # A per-request envelope (protocol 2026-07-28 and later) requires resultType.
            result["resultType"] = "complete"
        self._send_client({"jsonrpc": "2.0", "id": message["id"], "result": result})

    def _audit(self, decision: Decision, **extra: Any) -> None:
        record = self.guard.decision_record(decision)
        record.update(integration="mcp-proxy", server=self.server_name, **extra)
        self.guard.audit.append("decision", self.guard.session, record)

    def _track_task_result(self, message: dict[str, Any]) -> None:
        """Observe the result of a task-augmented ``tools/call`` when it is fetched."""
        params = message.get("params")
        task_id = params.get("taskId") if isinstance(params, dict) else None
        request_id = message.get("id")
        if not isinstance(task_id, str) or not _valid_id(request_id):
            return
        with self._state_lock:
            call = self._tasks.get(task_id)
            if call is not None:
                self._calls[request_id] = call

    def _cancel_pending(self, message: dict[str, Any]) -> bool:
        """Mark a call awaiting confirmation as cancelled; return whether one matched."""
        params = message.get("params")
        request_id = params.get("requestId") if isinstance(params, dict) else None
        if not _valid_id(request_id):
            return False
        with self._state_lock:
            pending = self._pending.get(request_id)
        if pending is None:
            return False
        pending.cancelled.set()
        if pending.elicitation is not None:
            waiter = self._waiters.get(pending.elicitation)
            if waiter is not None:
                waiter[0].set()
        return True

    def _confirm_via_queue(
        self, message: dict[str, Any], tool: str, args: Any, decision: Decision
    ) -> None:
        outcome = self.queue.request(ApprovalRequest.for_decision(self.guard.session, decision))
        apply_outcome(decision, outcome)
        self._audit(decision)
        if decision.effective == Action.ALLOW:
            self._forward_call(message, tool, args)
        else:
            self._refuse(message, decision)

    def _confirm_via_elicitation(
        self, message: dict[str, Any], tool: str, args: Any, decision: Decision, pending: _Pending
    ) -> None:
        # Unguessable, so a server cannot make the client's answer to one of its own
        # requests resolve the proxy's question.
        request_id = f"toolguard-{secrets.token_hex(12)}"
        event: threading.Event = threading.Event()
        box: list[dict[str, Any]] = []
        with self._state_lock:
            self._issued.add(request_id)
            self._waiters[request_id] = (event, box)
            pending.elicitation = request_id
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
        answered = event.wait(self.elicitation_timeout) and bool(box)
        with self._state_lock:
            self._waiters.pop(request_id, None)
            self._pending.pop(message["id"], None)
        cancelled = pending.cancelled.is_set()
        if not answered:
            reason = "the call was cancelled" if cancelled else "no answer in time"
            self._send_client(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": request_id, "reason": reason},
                }
            )
        response = box[0] if box else {}
        result = response.get("result")
        content = result.get("content") if isinstance(result, dict) else None
        approved = (
            answered
            and not cancelled
            and isinstance(result, dict)
            and result.get("action") == "accept"
            and isinstance(content, dict)
            and content.get("approve") is True
        )
        decision.approval_status = "approved" if approved else "denied"
        decision.approved_by = "mcp-elicitation" if answered else None
        decision.effective = Action.ALLOW if approved else Action.BLOCK
        if cancelled:
            # The client gave up on the call: run nothing and send no response.
            self._audit(decision, cancelled=True)
            return
        self._audit(decision)
        if approved:
            self._forward_call(message, tool, args)
        else:
            self._refuse(message, decision)

    def _resolve_elicitation(self, message: dict[str, Any]) -> bool:
        """Deliver an answer to an elicitation sent by the proxy; return whether it was one."""
        request_id = message.get("id")
        if not isinstance(request_id, str):
            return False
        with self._state_lock:
            if request_id not in self._issued:
                return False  # An answer to a request of the server: relay it
            waiter = self._waiters.get(request_id)
        if waiter is not None:
            event, box = waiter
            box.append(message)
            event.set()
        return True  # Late answers to the proxy's own questions are dropped

    # ------------------------------------------------------------------ server -> client

    def handle_server_line(self, line: bytes) -> None:
        """Relay a server message, recording the results of forwarded source calls."""
        try:
            # Decode as a tolerant client would, so what it reads is what gets observed.
            message = json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            message = None
        if isinstance(message, dict) and "method" not in message:
            self._observe_response(message)
        self._write_client(line if line.endswith(b"\n") else line + b"\n")

    def _observe_response(self, message: dict[str, Any]) -> None:
        request_id = message.get("id")
        if not _valid_id(request_id):
            return
        with self._state_lock:
            call = self._calls.pop(request_id, None)
        result = message.get("result")
        if call is None or not isinstance(result, dict):
            return
        tool, args, fields = call
        task = result.get("task")
        if isinstance(task, dict) and isinstance(task.get("taskId"), str):
            # A task-augmented call: the content arrives later, through tasks/result.
            with self._state_lock:
                self._tasks[task["taskId"]] = call
            return
        payload = {k: result.get(k) for k in fields}
        self.guard.observe(tool, payload, args)
