"""Message-level guard of the MCP proxy, shared by its stdio and HTTP transports.

Calls are evaluated as ``mcp__<server-name>__<tool>`` (Claude Code naming), so the
presets apply to any client. Results that reach the model are observed as sources:
those of tools, and those of ``resources/read`` (including reads of resource
templates) and ``prompts/get``, under the names ``mcp__<server-name>__resources/read``
and ``mcp__<server-name>__prompts/get``, which no real tool can take (tool names
cannot contain ``/``). The URI of a ``resources/read`` is also evaluated as a sink,
since the server fetches it. Confirmations use MCP elicitation when the client
supports it, since the model cannot answer an elicitation; otherwise they go to the
approval queue, whose one-time code reaches the human only through an out-of-band
notifier (never the error text the model reads).

The core knows nothing about the wire. A transport parses each client message and
hands it to :meth:`GuardCore.handle` with a :class:`Peer` that sends answers back to
where the message came from and forwards it to the server; it reports the response
to every forwarded request it was asked to track with :meth:`GuardCore.observe`.
Per-client state (the elicitation capability, calls awaiting a confirmation, tasks)
lives in a :class:`ClientState`: one per stdio connection or HTTP session.
"""

from __future__ import annotations

import json
import secrets
import threading
from collections.abc import Callable
from typing import Any, NamedTuple, Protocol

from ..approvals import ApprovalRequest, QueueApprover, apply_outcome
from ..guard import Guard
from ..model import Action, Decision
from ..redact import redact_args

ELICITATION_TIMEOUT = 300.0  # Seconds to wait for the user's answer

# Request metadata that marks the stateless revision (2026-07-28), which has no initialize.
PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# A refused request that has no result to carry the explanation (a resource read): an
# implementation-defined server error (-32000 to -32019) that the SDKs do not use.
REFUSED = -32003

# Requests other than ``tools/call`` whose results reach the model: the parameters
# observed as the call's arguments and the result fields that carry the content.
OBSERVED_READS = {
    "resources/read": (("uri",), ("contents",)),
    "prompts/get": (("name", "arguments"), ("description", "messages")),
}
TOOL_RESULT_FIELDS = ("content", "structuredContent")


def valid_id(value: Any) -> bool:
    """Return whether ``value`` is a usable JSON-RPC request id (string or integer)."""
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


def error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    """Return a JSON-RPC error response."""
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class Tracked(NamedTuple):
    """A forwarded request whose result is observed as a source.

    ``tool`` is the source name, ``args`` its arguments and ``fields`` the result
    fields that carry the content.
    """

    tool: str
    args: Any
    fields: tuple[str, ...]


class Peer(Protocol):
    """The transport side of one client message."""

    def reply(self, message: dict[str, Any]) -> None:
        """Send a message to the client about this one (an answer, an elicitation)."""

    def forward(self, message: Any, raw: bytes | None, tracked: Tracked | None) -> None:
        """Send this message to the server; ``raw`` holds its exact bytes when known.

        A ``tracked`` request's response must be passed to :meth:`GuardCore.observe`.
        """

    def drop(self) -> None:
        """Note that this request will get no answer (it was cancelled while pending)."""


class _Pending:
    """A request waiting for the user's confirmation."""

    def __init__(self) -> None:
        self.cancelled = threading.Event()
        self.elicitation: str | None = None


class ClientState:
    """What the core remembers about one client connection or session."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.elicitation = False  # The client accepts form-mode elicitation requests
        # Forwarded requests whose responses are matched by id: for transports that do
        # not carry the request with its response (stdio).
        self.calls: dict[Any, Tracked] = {}
        # Tasks created by a task-augmented ``tools/call`` -> the call.
        self.tasks: dict[str, Tracked] = {}
        # Client request ids of requests waiting for a confirmation.
        self.pending: dict[Any, _Pending] = {}
        # Elicitations sent by the proxy: every id issued, and the ones still awaited.
        self.issued: set[str] = set()
        self.waiters: dict[str, tuple[threading.Event, list[dict[str, Any]]]] = {}

    def cancel_all(self) -> None:
        """Cancel every pending confirmation (the client went away)."""
        with self.lock:
            pending = list(self.pending.values())
            waiters = dict(self.waiters)
        for item in pending:
            item.cancelled.set()
            if item.elicitation is not None and item.elicitation in waiters:
                waiters[item.elicitation][0].set()


class GuardCore:
    """Guard the client messages of an MCP connection and observe what reaches the model.

    Blocked calls never reach the server: the core answers them with an ``isError``
    result that explains the decision.
    """

    def __init__(
        self,
        guard: Guard,
        server_name: str,
        *,
        queue: QueueApprover | None = None,
        elicitation_timeout: float = ELICITATION_TIMEOUT,
        integration: str = "mcp-proxy",
    ) -> None:
        self.guard = guard
        self.server_name = server_name
        self.elicitation_timeout = elicitation_timeout
        self.integration = integration
        # Without configured notifiers the queue denies (fail closed).
        self.queue = queue or QueueApprover(guard.store, clock=guard.clock, audit=guard.audit)

    # ------------------------------------------------------------------ client -> server

    def handle(self, message: Any, raw: bytes | None, state: ClientState, peer: Peer) -> None:
        """Guard one client message (not a batch) and forward it, answer it or drop it."""
        if not isinstance(message, dict):
            peer.reply(error(None, INVALID_REQUEST, "Invalid Request"))
            return
        method = message.get("method")
        if method is None and self._resolve_elicitation(message, state):
            return
        if method == "initialize":
            self._note_capabilities(message, state)
        elif method == "tools/call":
            self._guard_call(message, state, peer)
            return
        elif method == "resources/read":
            self._guard_read(message, raw, state, peer)
            return
        elif method == "tasks/result":
            peer.forward(message, raw, self._task_call(message, state))
            return
        elif isinstance(method, str) and method in OBSERVED_READS:
            peer.forward(message, raw, self._read_call(message, method))
            return
        elif method == "notifications/cancelled" and self._cancel_pending(message, state):
            return
        peer.forward(message, raw, None)

    def _note_capabilities(self, message: dict[str, Any], state: ClientState) -> None:
        params = message.get("params")
        capabilities = params.get("capabilities") if isinstance(params, dict) else None
        elicitation = capabilities.get("elicitation") if isinstance(capabilities, dict) else None
        # An empty object means form mode, the only mode the proxy uses.
        state.elicitation = isinstance(elicitation, dict) and (
            not elicitation or "form" in elicitation
        )

    def tool_name(self, message: dict[str, Any]) -> tuple[str, Any]:
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

    def _guard_call(self, message: dict[str, Any], state: ClientState, peer: Peer) -> None:
        if "id" not in message:
            return  # A tools/call notification is invalid and has nobody to answer: drop it
        request_id = message["id"]
        if not valid_id(request_id):
            peer.reply(error(None, INVALID_REQUEST, "Invalid Request: bad id"))
            return
        try:
            tool, args = self.tool_name(message)
        except ValueError as exc:
            peer.reply(error(request_id, INVALID_PARAMS, f"Invalid params: {exc}"))
            return
        # A call is forwarded as re-encoded JSON, never as received.
        self._decide(
            message,
            self.guard.evaluate(tool, args),
            state,
            peer,
            lambda: peer.forward(message, None, Tracked(tool, args, TOOL_RESULT_FIELDS)),
            lambda decision: peer.reply(self._refusal(message, decision)),
        )

    def _guard_read(
        self, message: dict[str, Any], raw: bytes | None, state: ClientState, peer: Peer
    ) -> None:
        """Guard the URI of a ``resources/read``, which the server may fetch from anywhere.

        The read is evaluated as ``mcp__<server-name>__resources/read`` with its ``uri``,
        so a policy can treat URIs that leave the machine as egress. A read the policy
        does not refuse is relayed as received and its result observed.
        """
        params = message.get("params")
        if not isinstance(params, dict):
            peer.forward(message, raw, None)  # No URI to check: the server answers an error
            return
        tool = f"mcp__{self.server_name}__resources/read"
        args = {"uri": params["uri"]} if "uri" in params else {}
        decision = self.guard.evaluate(tool, args)

        def forward() -> None:
            peer.forward(message, raw, self._read_call(message, "resources/read"))

        if decision.category is None and not decision.reasons:
            forward()  # Not a sink: nothing to decide or audit
        elif not valid_id(message.get("id")):
            if decision.mode == "monitor" or decision.action == Action.ALLOW:
                peer.forward(message, raw, None)  # An invalid notification, harmless URI
        else:
            self._decide(
                message,
                decision,
                state,
                peer,
                forward,
                lambda d: peer.reply(error(message["id"], REFUSED, d.explain())),
            )

    def _decide(
        self,
        message: dict[str, Any],
        decision: Decision,
        state: ClientState,
        peer: Peer,
        forward: Callable[[], None],
        refuse: Callable[[Decision], None],
    ) -> None:
        """Run ``forward`` or ``refuse`` for a guarded request, asking a human if required."""
        if decision.mode == "monitor" or decision.action == Action.ALLOW:
            decision.effective = Action.ALLOW
            self.audit(decision)
            forward()
        elif decision.action == Action.BLOCK:
            self.audit(decision)
            refuse(decision)
        elif state.elicitation:
            pending = _Pending()
            with state.lock:
                state.pending[message["id"]] = pending
            # Wait off the caller, which must keep reading to receive the answer.
            threading.Thread(
                target=self._confirm_via_elicitation,
                args=(message, decision, state, peer, pending, forward, refuse),
                daemon=True,
            ).start()
        else:
            self._confirm_via_queue(decision, forward, refuse)

    def _read_call(self, message: dict[str, Any], method: str) -> Tracked | None:
        """Return how to observe a ``resources/read`` or ``prompts/get`` result."""
        params = message.get("params")
        if not valid_id(message.get("id")) or not isinstance(params, dict):
            return None  # The server answers it with an error, which is not observed
        names, fields = OBSERVED_READS[method]
        args = {name: params[name] for name in names if name in params}
        return Tracked(f"mcp__{self.server_name}__{method}", args, fields)

    def _task_call(self, message: dict[str, Any], state: ClientState) -> Tracked | None:
        """Return the task-augmented ``tools/call`` whose result a ``tasks/result`` fetches."""
        params = message.get("params")
        task_id = params.get("taskId") if isinstance(params, dict) else None
        if not isinstance(task_id, str) or not valid_id(message.get("id")):
            return None
        with state.lock:
            return state.tasks.get(task_id)

    def _refusal(self, message: dict[str, Any], decision: Decision) -> dict[str, Any]:
        result: dict[str, Any] = {
            "content": [{"type": "text", "text": decision.explain()}],
            "isError": True,
        }
        params = message.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        if isinstance(meta, dict) and PROTOCOL_VERSION_META in meta:
            # A per-request envelope (protocol 2026-07-28 and later) requires resultType.
            result["resultType"] = "complete"
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    def audit(self, decision: Decision, **extra: Any) -> None:
        """Append a decision to the audit log, marked with this integration and server."""
        record = self.guard.decision_record(decision)
        record.update(integration=self.integration, server=self.server_name, **extra)
        self.guard.audit.append("decision", self.guard.session, record)

    def _cancel_pending(self, message: dict[str, Any], state: ClientState) -> bool:
        """Mark a call awaiting confirmation as cancelled; return whether one matched."""
        params = message.get("params")
        request_id = params.get("requestId") if isinstance(params, dict) else None
        if not valid_id(request_id):
            return False
        return self.cancel(request_id, state)

    def cancel(self, request_id: Any, state: ClientState) -> bool:
        """Cancel the confirmation of ``request_id``; return whether it was pending."""
        with state.lock:
            pending = state.pending.get(request_id)
            asked = pending.elicitation if pending is not None else None
            waiter = state.waiters.get(asked) if asked is not None else None
        if pending is None:
            return False
        pending.cancelled.set()
        if waiter is not None:
            waiter[0].set()
        return True

    def _confirm_via_queue(
        self, decision: Decision, forward: Callable[[], None], refuse: Callable[[Decision], None]
    ) -> None:
        outcome = self.queue.request(ApprovalRequest.for_decision(self.guard.session, decision))
        apply_outcome(decision, outcome)
        self.audit(decision)
        if decision.effective == Action.ALLOW:
            forward()
        else:
            refuse(decision)

    def _confirm_via_elicitation(
        self,
        message: dict[str, Any],
        decision: Decision,
        state: ClientState,
        peer: Peer,
        pending: _Pending,
        forward: Callable[[], None],
        refuse: Callable[[Decision], None],
    ) -> None:
        # Unguessable, so a server cannot make the client's answer to one of its own
        # requests resolve the proxy's question.
        request_id = f"toolguard-{secrets.token_hex(12)}"
        event = threading.Event()
        box: list[dict[str, Any]] = []
        with state.lock:
            state.issued.add(request_id)
            state.waiters[request_id] = (event, box)
            pending.elicitation = request_id
        peer.reply(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "elicitation/create",
                "params": {
                    "message": decision.explain()
                    + f"\n\nArguments (redacted): {json.dumps(redact_args(decision.args, 200))}",
                    "requestedSchema": {
                        "type": "object",
                        "properties": {
                            "approve": {
                                "type": "boolean",
                                "title": f"Allow {decision.tool}?",
                                "description": "Approve this single tool call",
                            }
                        },
                        "required": ["approve"],
                    },
                },
            }
        )
        answered = event.wait(self.elicitation_timeout) and bool(box)
        with state.lock:
            state.waiters.pop(request_id, None)
            state.pending.pop(message["id"], None)
        cancelled = pending.cancelled.is_set()
        if not answered:
            reason = "the call was cancelled" if cancelled else "no answer in time"
            peer.reply(
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
            self.audit(decision, cancelled=True)
            peer.drop()
            return
        self.audit(decision)
        if approved:
            forward()
        else:
            refuse(decision)

    def _resolve_elicitation(self, message: dict[str, Any], state: ClientState) -> bool:
        """Deliver an answer to an elicitation sent by the proxy; return whether it was one."""
        request_id = message.get("id")
        if not isinstance(request_id, str):
            return False
        with state.lock:
            if request_id not in state.issued:
                return False  # An answer to a request of the server: relay it
            waiter = state.waiters.get(request_id)
        if waiter is not None:
            event, box = waiter
            box.append(message)
            event.set()
        return True  # Late answers to the proxy's own questions are dropped

    # ------------------------------------------------------------------ server -> client

    def observe(self, tracked: Tracked, message: Any, state: ClientState) -> None:
        """Record the server's response to a tracked request as a source."""
        result = message.get("result") if isinstance(message, dict) else None
        if not isinstance(result, dict):
            return  # An error: nothing reached the model
        tool, args, fields = tracked
        task = result.get("task")
        if isinstance(task, dict) and isinstance(task.get("taskId"), str):
            # A task-augmented call: the content arrives later, through tasks/result.
            with state.lock:
                state.tasks[task["taskId"]] = Tracked(tool, args, fields)
            return
        payload = {k: result.get(k) for k in fields}
        self.guard.observe(tool, payload, args)
