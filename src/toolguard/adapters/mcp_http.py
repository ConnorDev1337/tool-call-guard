"""Streamable HTTP transport of the MCP proxy.

The proxy listens on a loopback HTTP endpoint and guards every client message with
the same :class:`~.mcp_core.GuardCore` as the stdio proxy, then forwards it either
to an upstream Streamable HTTP server or to a stdio server process it starts:

* **Upstream mode** (``--upstream URL``) relays each POST, GET and DELETE to the
  upstream endpoint. Responses (JSON or SSE) are parsed and re-encoded event by
  event, so the client reads exactly what was inspected; ``Mcp-Session-Id``,
  ``MCP-Protocol-Version``, ``Last-Event-ID`` and credentials such as
  ``Authorization`` pass through unchanged and are never logged. Sessions,
  resumability and the stateless revision (2026-07-28) are the upstream's.
* **Stdio mode** (a server command) makes the proxy the Streamable HTTP server of a
  stdio process: it issues the ``Mcp-Session-Id`` on ``initialize``, routes the
  server's responses and progress to the POST that caused them and other server
  messages to the client's GET stream.

Security defaults follow the transport's DNS-rebinding guidance: the proxy binds to
loopback, rejects a ``Host`` that does not name it (421) and an ``Origin`` that is
not a loopback page (403), and caps body sizes and idle times. Upstream redirects
are refused rather than relayed, since a client that followed one would reach the
server around the guard, and batches are refused (the transport dropped them in
2025-06-18; the proxy will not forward a message it has not inspected alone).
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import http.client
import ipaddress
import json
import queue
import secrets
import socket
import ssl
import sys
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, NamedTuple
from urllib.parse import urlsplit

from ..approvals import QueueApprover
from ..guard import Guard
from .mcp_core import (
    ELICITATION_TIMEOUT,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    ClientState,
    GuardCore,
    Tracked,
    error,
    valid_id,
)
from .mcp_proxy import SHUTDOWN_GRACE, StdioServer

DEFAULT_PATH = "/mcp"
MAX_BODY = 4 * 1024 * 1024  # Bytes of one client POST body
MAX_MESSAGE = 64 * 1024 * 1024  # Bytes of one upstream message or SSE event
CLIENT_TIMEOUT = 30.0  # Seconds to read a client request, or to write to a stalled client
UPSTREAM_TIMEOUT = 300.0  # Seconds the upstream may stay silent (SDK client default)
CONNECT_TIMEOUT = 10.0
KEEPALIVE = 15.0  # Seconds between SSE comments on a quiet stream
MAX_CONNECTIONS = 64
MAX_SESSIONS = 1024
MAX_TRACKED = 4096  # Forwarded requests per session still awaiting their response
MAX_BUFFERED = 256  # Server messages kept for a GET stream that is not open (stdio mode)

HEADER_MISMATCH = -32020  # HTTP headers that contradict the body (protocol 2026-07-28)

SESSION = "mcp-session-id"
VERSION = "mcp-protocol-version"
LAST_EVENT = "last-event-id"
METHOD_HEADER = "mcp-method"
NAME_HEADER = "mcp-name"
PARAM_PREFIX = "mcp-param-"
# Body parameter mirrored in the Mcp-Name header, per method (protocol 2026-07-28).
NAMED = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}

LOOPBACK_NAMES = ("127.0.0.1", "localhost", "[::1]")
# Headers that describe one connection, or that the proxy sets itself.
_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
    "host",
}
# Client headers that are not passed on: the proxy is the upstream's client, not a browser.
_NOT_FORWARDED = _HOP | {"accept-encoding", "origin", "referer", "expect", "cookie2"}
_STATUS_OF_ERROR = {
    PARSE_ERROR: 400,
    INVALID_REQUEST: 400,
    INVALID_PARAMS: 400,
    HEADER_MISMATCH: 400,
    METHOD_NOT_FOUND: 404,
}
_B64 = "=?base64?"


def is_loopback(host: str) -> bool:
    """Return whether ``host`` (a name, or an address with or without brackets) is loopback."""
    name = host.strip("[]").lower()
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def decode_header_value(value: str) -> str | None:
    """Decode an ``Mcp-Name`` or ``Mcp-Param-*`` value (``=?base64?...?=`` or verbatim)."""
    if not (value.startswith(_B64) and value.endswith("?=")):
        return value
    payload = value[len(_B64) : -2]
    try:
        data = base64.b64decode(payload, validate=True)
        return data.decode("utf-8") if base64.b64encode(data).decode() == payload else None
    except (binascii.Error, UnicodeDecodeError):
        return None


def _scalars(value: Any) -> Iterator[str]:
    """Yield how each scalar of ``value`` may be written in an ``Mcp-Param-*`` header."""
    if isinstance(value, dict):
        for item in value.values():
            yield from _scalars(item)
    elif isinstance(value, list):
        for item in value:
            yield from _scalars(item)
    elif isinstance(value, bool):
        yield "true" if value else "false"
    elif isinstance(value, int | float):
        # Clients render numbers as their language does (Python str, JavaScript String).
        yield str(value)
        yield json.dumps(value)
        if isinstance(value, float) and value.is_integer():
            yield str(int(value))
    elif isinstance(value, str):
        yield value


def header_mismatch(message: dict[str, Any], headers: dict[str, str]) -> str | None:
    """Return why routing headers contradict a request body, or ``None`` if they agree.

    Protocol 2026-07-28 mirrors the method, the tool, prompt or resource name and
    selected tool arguments in headers. They reach the server, so a value that is
    not in the inspected body would carry data around the guard.
    """
    method = message.get("method")
    if METHOD_HEADER in headers and headers[METHOD_HEADER] != method:
        return "the Mcp-Method header does not match the body"
    params = message.get("params")
    params = params if isinstance(params, dict) else {}
    if NAME_HEADER in headers:
        key = NAMED.get(method) if isinstance(method, str) else None
        if key is None or decode_header_value(headers[NAME_HEADER]) != params.get(key):
            return "the Mcp-Name header does not match the body"
    names = [h for h in headers if h.startswith(PARAM_PREFIX)]
    if names:
        allowed = set(_scalars(params.get("arguments"))) if method == "tools/call" else set()
        for name in names:
            if decode_header_value(headers[name]) not in allowed:
                return f"the {name} header is not an argument of the call"
    return None


def _modern(version: str | None) -> bool:
    """Return whether a protocol version is the stateless revision or later."""
    return bool(version) and str(version) >= "2026-07-28"


# --------------------------------------------------------------------------- SSE


class SseEvent(NamedTuple):
    """One server-sent event; ``None`` fields were absent from the block."""

    data: str | None = None
    event: str | None = None
    id: str | None = None
    retry: str | None = None

    def encode(self) -> bytes:
        """Return the event as written by the proxy (one field per line, LF endings)."""
        lines = []
        if self.event is not None:
            lines.append(f"event: {self.event}")
        if self.id is not None:
            lines.append(f"id: {self.id}")
        if self.retry is not None:
            lines.append(f"retry: {self.retry}")
        if self.data is not None:
            lines.extend(f"data: {line}" for line in self.data.split("\n"))
        return ("\n".join(lines) + "\n\n").encode("utf-8")


class SseParser:
    """Incremental parser of a ``text/event-stream`` body (WHATWG event stream rules).

    :meth:`feed` returns the complete events in the bytes it is given, and ``None``
    for each comment line, so a relay can pass keepalives on.
    """

    def __init__(self, max_event: int = MAX_MESSAGE) -> None:
        self.max_event = max_event
        self._buffer = b""
        self._started = False
        self._fields: dict[str, str] = {}
        self._data: list[str] = []
        self._size = 0

    def feed(self, chunk: bytes) -> list[SseEvent | None]:
        """Parse ``chunk``; raise ``ValueError`` if an event exceeds the size limit."""
        self._buffer += chunk
        out: list[SseEvent | None] = []
        while True:
            index = min(
                (i for i in (self._buffer.find(b"\n"), self._buffer.find(b"\r")) if i >= 0),
                default=-1,
            )
            if index < 0:
                break
            if self._buffer[index : index + 1] == b"\r" and index + 1 == len(self._buffer):
                break  # A CR at the end may be the first half of CRLF
            end = index + 2 if self._buffer[index : index + 2] == b"\r\n" else index + 1
            raw, self._buffer = self._buffer[:index], self._buffer[end:]
            line = raw.decode("utf-8", "replace")
            if not self._started:
                self._started = True
                line = line.removeprefix("\ufeff")
            out.extend(self._line(line))
        if len(self._buffer) + self._size > self.max_event:
            raise ValueError("server-sent event too large")
        return out

    def _line(self, line: str) -> list[SseEvent | None]:
        if not line:
            if not self._data and not self._fields:
                return []
            event = SseEvent(
                data="\n".join(self._data) if self._data else None,
                event=self._fields.get("event"),
                id=self._fields.get("id"),
                retry=self._fields.get("retry"),
            )
            self._fields, self._data, self._size = {}, [], 0
            return [event]
        if line.startswith(":"):
            return [None]
        name, _, value = line.partition(":")
        value = value.removeprefix(" ")
        self._size += len(line)
        if self._size > self.max_event:
            raise ValueError("server-sent event too large")
        if name == "data":
            self._data.append(value)
        elif name == "event":
            self._fields["event"] = value
        elif name == "id" and "\0" not in value:
            self._fields["id"] = value
        elif name == "retry" and value.isdigit():
            self._fields["retry"] = value
        return []


def _parse(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return _UNPARSED


_UNPARSED = object()


def _encode(message: Any) -> bytes:
    return json.dumps(message, ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------------- upstream


class Upstream:
    """An upstream Streamable HTTP endpoint, reached with one connection per request."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = UPSTREAM_TIMEOUT,
        connect_timeout: float = CONNECT_TIMEOUT,
        context: ssl.SSLContext | None = None,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"not an http(s) URL: {url!r}")
        if parts.username or parts.password:
            raise ValueError("credentials in the upstream URL are not supported; use a header")
        self.url = url
        self.https = parts.scheme == "https"
        self.host = parts.hostname
        self.port = parts.port or (443 if self.https else 80)
        self.netloc = parts.netloc
        self.target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.context = context

    @property
    def loopback(self) -> bool:
        """Whether the upstream is on this machine."""
        return is_loopback(self.host)

    def request(
        self, method: str, headers: list[tuple[str, str]], body: bytes | None = None
    ) -> UpstreamReply:
        """Send a request and return the response once its headers have arrived."""
        conn: http.client.HTTPConnection
        if self.https:
            context = self.context or ssl.create_default_context()
            conn = http.client.HTTPSConnection(
                self.host, self.port, timeout=self.connect_timeout, context=context
            )
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.connect_timeout)
        try:
            conn.connect()
            if conn.sock is not None:
                conn.sock.settimeout(self.timeout)
            conn.putrequest(method, self.target, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", self.netloc)
            conn.putheader("Accept-Encoding", "identity")
            for name, value in headers:
                conn.putheader(name, value)
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            return UpstreamReply(conn, conn.getresponse())
        except BaseException:
            conn.close()
            raise


class UpstreamReply:
    """An upstream response being read; :meth:`close` aborts it."""

    def __init__(self, conn: http.client.HTTPConnection, response: http.client.HTTPResponse):
        self.conn = conn
        self.response = response
        self.status = response.status
        self.headers = response.getheaders()

    def header(self, name: str) -> str | None:
        """Return the first value of header ``name`` (case-insensitive)."""
        return self.response.getheader(name)

    @property
    def content_type(self) -> str:
        """The media type, lowercase, without parameters."""
        return (self.header("Content-Type") or "").split(";")[0].strip().lower()

    def read_body(self, limit: int = MAX_MESSAGE) -> bytes:
        """Read the whole body; raise ``ValueError`` beyond ``limit`` bytes."""
        data = self.response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("upstream response too large")
        return data

    def chunks(self) -> Iterator[bytes]:
        """Yield the body as it arrives."""
        while True:
            chunk = self.response.read1(65536)
            if not chunk:
                return
            yield chunk

    def close(self) -> None:
        """Close the connection, aborting the response if it is still being read."""
        with contextlib.suppress(OSError):
            if self.conn.sock is not None:
                self.conn.sock.shutdown(2)
        self.conn.close()

    def __enter__(self) -> UpstreamReply:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def passed_back(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Return the upstream response headers that go back to the client."""
    listed = {
        token.strip().lower()
        for name, value in headers
        if name.lower() == "connection"
        for token in value.split(",")
    }
    dropped = _HOP | listed | {"date", "server"}  # The proxy writes its own
    return [(n, v) for n, v in headers if n.lower() not in dropped]


# --------------------------------------------------------------------------- client side


class ClientGone(Exception):
    """The client closed the connection or stopped reading."""


class ClientResponse:
    """The proxy's HTTP response to one client request, decided lazily.

    A response is either a plain body (JSON or empty) or an SSE stream written in
    chunks; it is committed by the first thing written.
    """

    def __init__(self, handler: BaseHTTPRequestHandler) -> None:
        self.handler = handler
        self.mode: str | None = None  # None, "sse" or "done"
        self.headers: list[tuple[str, str]] = []  # Added to whatever is sent

    def _write(self, data: bytes) -> None:
        try:
            self.handler.wfile.write(data)
            self.handler.wfile.flush()
        except (OSError, ValueError) as exc:
            self.mode = "done"
            self.handler.close_connection = True
            raise ClientGone() from exc

    def _head(self, status: int, headers: list[tuple[str, str]]) -> None:
        handler = self.handler
        handler.send_response_only(status)
        handler.send_header("Date", handler.date_time_string())
        seen = set()
        for name, value in [*headers, *self.headers]:
            if name.lower() not in seen:
                seen.add(name.lower())
                handler.send_header(name, value)
        handler.end_headers()

    def body(
        self, status: int, data: bytes, headers: list[tuple[str, str]] = (), ctype: str = ""
    ) -> None:
        """Send a complete response (an empty body for ``202``/``204``)."""
        if self.mode is not None:
            raise RuntimeError("response already started")
        self.mode = "done"
        extra = [("Content-Type", ctype)] if ctype and data else []
        if status not in (204, 304):
            extra.append(("Content-Length", str(len(data))))
        try:
            self._head(status, [*extra, *headers])
        except (OSError, ValueError) as exc:
            raise ClientGone() from exc
        if data:
            self._write(data)

    def json(self, message: Any, status: int = 200, headers: list[tuple[str, str]] = ()) -> None:
        """Send one JSON-RPC message as an ``application/json`` body."""
        self.body(status, _encode(message), headers, "application/json")

    def start_sse(self, status: int = 200, headers: list[tuple[str, str]] = ()) -> None:
        """Commit to an SSE stream."""
        if self.mode is not None:
            raise RuntimeError("response already started")
        self.mode = "sse"
        base = [
            ("Content-Type", "text/event-stream"),
            ("Cache-Control", "no-cache, no-transform"),
            ("X-Accel-Buffering", "no"),
            ("Transfer-Encoding", "chunked"),
        ]
        ours = {"content-type", "cache-control", "transfer-encoding", "content-length"}
        try:
            self._head(status, [*base, *((n, v) for n, v in headers if n.lower() not in ours)])
        except (OSError, ValueError) as exc:
            self.mode = "done"
            raise ClientGone() from exc

    def chunk(self, data: bytes) -> None:
        """Write bytes to the SSE stream."""
        if self.mode != "sse":
            raise RuntimeError("no SSE stream")
        self._write(f"{len(data):X}\r\n".encode() + data + b"\r\n")

    def event(self, message: Any) -> None:
        """Write one JSON-RPC message as an SSE event, starting the stream if needed."""
        if self.mode is None:
            self.start_sse()
        self.chunk(SseEvent(data=_encode(message).decode("utf-8")).encode())

    def ping(self) -> None:
        """Write a keepalive comment (also detects a client that went away)."""
        if self.mode == "sse":
            self.chunk(b": keepalive\n\n")

    def finish(self) -> None:
        """End the SSE stream (or send an empty stream if nothing was written)."""
        if self.mode is None:
            self.start_sse()
        if self.mode == "sse":
            self.mode = "done"
            with contextlib.suppress(ClientGone):
                self._write(b"0\r\n\r\n")


def _status_of(message: dict[str, Any]) -> int:
    err = message.get("error")
    code = err.get("code") if isinstance(err, dict) else None
    return _STATUS_OF_ERROR.get(code, 200) if isinstance(code, int) else 200


# --------------------------------------------------------------------------- exchanges


class Exchange:
    """One client request to the proxy (POST or GET) and everything written back.

    It is the :class:`~.mcp_core.Peer` of the message it carries. The core, the
    upstream reader and the stdio router push actions into its queue; the HTTP
    handler thread runs them, so only that thread writes to the client.
    """

    def __init__(
        self,
        front: HttpProxy,
        handler: ProxyHandler,
        state: ClientState,
        message: Any = None,
        session_id: str | None = None,
    ) -> None:
        self.front = front
        self.handler = handler
        self.state = state
        self.message = message
        self.session_id = session_id
        self.out = ClientResponse(handler)
        self.actions: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self.is_request = (
            isinstance(message, dict)
            and isinstance(message.get("method"), str)
            and "id" in message
        )
        self.request_id = message.get("id") if self.is_request else None
        self.tracked: Tracked | None = None
        self.answered = False  # The final response was written
        self.pending = True  # The core may still answer or forward (requests only)
        self.forwarded = False
        self.reader: UpstreamReply | None = None
        self.progress_token: Any = None

    # ---------------------------------------------------------------- Peer

    def reply(self, message: dict[str, Any]) -> None:
        """Queue a message written by the proxy for this client request."""
        self.actions.put(("reply", message))

    def forward(self, message: Any, raw: bytes | None, tracked: Tracked | None) -> None:
        """Queue the message for the server."""
        self.actions.put(("forward", message, raw, tracked))

    def drop(self) -> None:
        """End the request without an answer: it was cancelled while waiting."""
        self.actions.put(("drop",))

    # ---------------------------------------------------------------- running

    def run(self) -> None:
        """Run queued actions until the client has its answer or went away."""
        try:
            if not self.is_request:
                # The core handled it synchronously: forward it, answer it, or accept it.
                if self.actions.empty():
                    self.out.body(202, b"")
                    return
                while not self.actions.empty() and self.out.mode != "done":
                    self._do(self.actions.get())
                if self.out.mode is None:
                    self.out.body(202, b"")
                return
            while self.out.mode != "done":
                try:
                    action = self.actions.get(timeout=KEEPALIVE)
                except queue.Empty:
                    self.out.ping()
                    continue
                self._do(action)
        except ClientGone:
            self._client_gone()
        finally:
            if self.reader is not None:
                self.reader.close()
            self.front.backend.release(self)

    def _client_gone(self) -> None:
        if self.is_request and not self.answered and not self.forwarded:
            # Nobody could read the result of a call confirmed now: do not run it.
            self.front.core.cancel(self.request_id, self.state)

    def _do(self, action: tuple[Any, ...]) -> None:
        kind = action[0]
        if kind == "reply":
            self._reply(action[1])
        elif kind == "forward":
            self.forwarded = True
            _, message, raw, tracked = action
            if tracked is not None and self.is_request:
                self.tracked = tracked
                self.front.track(self.state, self.request_id, tracked)
            self.front.backend.forward(self, message, raw)
        elif kind == "drop":
            self.out.finish()
        elif kind == "event":
            self.relay_event(action[1])
        elif kind == "message":
            self.relay_message(action[1], action[2])
        elif kind == "end":
            self.out.finish()

    def _reply(self, message: dict[str, Any]) -> None:
        final = "method" not in message and (
            not self.is_request or message.get("id") in (self.request_id, None)
        )
        if not final:
            self.out.event(message)
            return
        self.answered = True
        if self.out.mode is None:
            self.out.json(message, _status_of(message))
        else:
            self.out.event(message)
            self.out.finish()

    # ---------------------------------------------------------------- server -> client

    def inspect(self, message: Any) -> None:
        """Observe the responses in a server message before the client reads it."""
        for item in message if isinstance(message, list) else [message]:
            if not isinstance(item, dict) or "method" in item or not valid_id(item.get("id")):
                continue
            item_id = item["id"]
            mine = self.is_request and item_id == self.request_id
            tracked = self.front.untrack(self.state, item_id, self.tracked if mine else None)
            if mine:
                tracked, self.tracked = self.tracked or tracked, None
                self.answered = True
            if tracked is not None:
                self.front.core.observe(tracked, item, self.state)

    def relay_event(self, event: SseEvent) -> None:
        """Inspect and write one upstream SSE event (or a keepalive for ``None``)."""
        if event is None:
            self.out.ping()
            return
        if event.data:
            message = _parse(event.data)
            if message is _UNPARSED:
                return  # Never relay what could not be inspected
            self.inspect(message)
        if self.out.mode is None:
            self.out.start_sse()
        self.out.chunk(event.encode())
        if self.answered:
            self.out.finish()  # The request has its response: the stream is complete

    def relay_message(self, text: str, message: Any) -> None:
        """Inspect and write one message from a stdio server."""
        self.inspect(message)
        if self.answered and self.out.mode is None:
            self.out.body(
                200, text.encode("utf-8"), self.front.session_headers(self), "application/json"
            )
            return
        if self.out.mode is None:
            self.out.start_sse(200, self.front.session_headers(self))
        self.out.chunk(SseEvent(data=text).encode())
        if self.answered:
            self.out.finish()

    def fail(self, status: int, reason: str) -> None:
        """Answer with an error the proxy writes itself (an upstream failure)."""
        text = f"toolguard: {reason}"
        if self.is_request:
            message = error(self.request_id, INTERNAL_ERROR, text)
            self.answered = True
            if self.out.mode is None:
                self.out.json(message, status)
            else:
                self.out.event(message)
                self.out.finish()
        elif self.out.mode is None:
            self.out.json(error(None, INTERNAL_ERROR, text), status)
        else:
            self.out.finish()


# --------------------------------------------------------------------------- backends


class UpstreamBackend:
    """Forward to an upstream Streamable HTTP server; sessions are the upstream's."""

    def __init__(self, front: HttpProxy, upstream: Upstream) -> None:
        self.front = front
        self.upstream = upstream
        self.lock = threading.Lock()
        self.states: OrderedDict[str | None, ClientState] = OrderedDict()

    def state_for(self, session_id: str | None, message: Any) -> ClientState:
        """Return the client state of a session (a new one for ``initialize``)."""
        if isinstance(message, dict) and message.get("method") == "initialize":
            return ClientState()
        with self.lock:
            state = self.states.get(session_id)
            if state is None:
                state = self.states[session_id] = ClientState()
                while len(self.states) > MAX_SESSIONS:
                    self.states.popitem(last=False)[1].cancel_all()
            self.states.move_to_end(session_id)
            return state

    def bind(self, session_id: str | None, state: ClientState) -> None:
        with self.lock:
            self.states[session_id] = state

    def end(self, session_id: str | None) -> None:
        with self.lock:
            state = self.states.pop(session_id, None)
        if state is not None:
            state.cancel_all()

    def upstream_headers(self, exchange: Exchange) -> list[tuple[str, str]]:
        handler = exchange.handler
        listed = {t.strip().lower() for t in handler.headers.get("Connection", "").split(",")}
        return [
            (name, value)
            for name, value in handler.headers.items()
            if name.lower() not in _NOT_FORWARDED and name.lower() not in listed
        ]

    def forward(self, exchange: Exchange, message: Any, raw: bytes | None) -> None:
        body = raw if raw is not None else _encode(message)
        self.relay(exchange, "POST", body)

    def relay(self, exchange: Exchange, method: str, body: bytes | None = None) -> None:
        """Send the client's request upstream and relay the response to it."""
        try:
            reply = self.upstream.request(method, self.upstream_headers(exchange), body)
        except (OSError, http.client.HTTPException, ValueError):
            exchange.fail(502, "the upstream MCP server is unreachable")
            return
        exchange.reader = reply
        if 300 <= reply.status < 400:
            exchange.fail(502, "the upstream MCP server redirected the request; not followed")
            return
        session_id = exchange.session_id
        new_id = reply.header("Mcp-Session-Id")
        if exchange.is_request and exchange.message.get("method") == "initialize":
            if 200 <= reply.status < 300:
                self.bind(new_id, exchange.state)
        elif (method == "DELETE" and reply.status in (200, 202, 204)) or (
            reply.status == 404 and session_id is not None
        ):
            self.end(session_id)  # Ended by the client, or unknown to the server
        headers = passed_back(reply.headers)
        if reply.status == 200 and reply.content_type == "text/event-stream":
            self._relay_stream(exchange, reply, headers)
            return
        try:
            data = reply.read_body()
        except (OSError, http.client.HTTPException, ValueError):
            exchange.fail(502, "the upstream MCP server sent an unreadable response")
            return
        if reply.content_type == "application/json" and data:
            message = _parse(data.decode("utf-8", "replace"))
            if message is _UNPARSED:
                exchange.fail(502, "the upstream MCP server sent a response that is not JSON")
                return
            exchange.inspect(message)
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                data = _encode(message)  # Relay what was inspected
            if exchange.out.mode == "sse":
                if not isinstance(message, dict):
                    exchange.fail(502, "the upstream MCP server sent an unexpected response")
                    return
                exchange.out.event(message)
                exchange.out.finish()
                return
        elif exchange.out.mode == "sse":
            exchange.fail(502, f"the upstream MCP server answered HTTP {reply.status}")
            return
        exchange.out.body(reply.status, data, headers)

    def _relay_stream(
        self, exchange: Exchange, reply: UpstreamReply, headers: list[tuple[str, str]]
    ) -> None:
        if exchange.out.mode is None:
            exchange.out.start_sse(200, headers)
        events = exchange.actions
        threading.Thread(target=self._read_stream, args=(reply, events), daemon=True).start()

    @staticmethod
    def _read_stream(reply: UpstreamReply, events: queue.Queue[tuple[Any, ...]]) -> None:
        parser = SseParser()
        try:
            for chunk in reply.chunks():
                for event in parser.feed(chunk):
                    events.put(("event", event))
        except (OSError, http.client.HTTPException, ValueError):
            pass  # A broken or oversized stream ends like a closed one
        events.put(("end",))

    def get(self, exchange: Exchange) -> None:
        """Relay a GET (the server's SSE stream, or its resumption)."""
        self.relay(exchange, "GET")
        exchange.is_request = False
        exchange.pending = False
        # Run the events of an SSE stream until it ends or the client goes away.
        while exchange.out.mode == "sse":
            try:
                action = exchange.actions.get(timeout=KEEPALIVE)
            except queue.Empty:
                exchange.out.ping()
                continue
            exchange._do(action)

    def delete(self, exchange: Exchange) -> None:
        self.relay(exchange, "DELETE")

    def release(self, exchange: Exchange) -> None:
        """Nothing to release: upstream connections close with their exchange."""


class _GetStream:
    """The client's open GET stream for one session (stdio mode)."""

    def __init__(self, exchange: Exchange) -> None:
        self.exchange = exchange


class StdioBackend(StdioServer):
    """Run a stdio server behind the proxy's HTTP endpoint (one client session at a time)."""

    def __init__(
        self,
        front: HttpProxy,
        command: list[str],
        *,
        shutdown_grace: float = SHUTDOWN_GRACE,
        popen: Callable[..., Any] | None = None,
    ) -> None:
        kwargs = {"popen": popen} if popen is not None else {}
        super().__init__(command, shutdown_grace=shutdown_grace, **kwargs)
        self.front = front
        self.lock = threading.Lock()
        self.session_id: str | None = None
        self.state = ClientState()  # Of the current session, or of session-less clients
        self.waiting: dict[Any, Exchange] = {}  # Forwarded request id -> its exchange
        self.progress: dict[Any, Exchange] = {}  # Progress token -> exchange
        self.get_stream: Exchange | None = None
        self.buffered: list[tuple[str, Any]] = []

    # ---------------------------------------------------------------- sessions

    def state_for(
        self, exchange_headers: dict[str, str], message: Any
    ) -> tuple[ClientState | None, str | None, int, str]:
        """Return the state and session of a POST, or an HTTP status and reason to refuse it."""
        session_id = exchange_headers.get(SESSION)
        with self.lock:
            if isinstance(message, dict) and message.get("method") == "initialize":
                if session_id is not None:
                    return None, None, 400, "initialize must not carry Mcp-Session-Id"
                self._end_locked()
                self.session_id = secrets.token_urlsafe(24)
                self.state = ClientState()
                return self.state, self.session_id, 0, ""
            if session_id is None:
                if self.session_id is not None and not _modern(exchange_headers.get(VERSION)):
                    return None, None, 400, "Mcp-Session-Id header is required"
                return self.state, None, 0, ""
            if session_id != self.session_id:
                return None, None, 404, "Session not found"
            return self.state, session_id, 0, ""

    def _end_locked(self) -> None:
        if self.get_stream is not None:
            self.get_stream.actions.put(("end",))
            self.get_stream = None
        self.state.cancel_all()
        self.buffered.clear()
        self.session_id = None

    # ---------------------------------------------------------------- client -> server

    def forward(self, exchange: Exchange, message: Any, raw: bytes | None) -> None:
        if exchange.is_request and isinstance(message, dict):
            params = message.get("params")
            meta = params.get("_meta") if isinstance(params, dict) else None
            token = meta.get("progressToken") if isinstance(meta, dict) else None
            with self.lock:
                self.waiting[exchange.request_id] = exchange
                if token is not None and isinstance(token, str | int):
                    self.progress[token] = exchange
                    exchange.progress_token = token
        if raw is not None:
            self._send_server_raw(raw)
        else:
            self._send_server(message)

    def release(self, exchange: Exchange) -> None:
        """Stop routing server messages to a finished exchange."""
        with self.lock:
            if self.waiting.get(exchange.request_id) is exchange:
                del self.waiting[exchange.request_id]
            if self.progress.get(exchange.progress_token) is exchange:
                del self.progress[exchange.progress_token]
            if self.get_stream is exchange:
                self.get_stream = None

    # ---------------------------------------------------------------- server -> client

    def handle_server_line(self, line: bytes) -> None:
        """Route one line of the server to the exchange it belongs to."""
        text = line.decode("utf-8", "replace").strip()
        message = _parse(text)
        if message is _UNPARSED:
            return  # Not JSON: a stray log line, which no client could use
        items = message if isinstance(message, list) else [message]
        for item in items:
            item_text = text if len(items) == 1 else _encode(item).decode("utf-8")
            self._route(item_text, item)

    def _route(self, text: str, message: Any) -> None:
        if not isinstance(message, dict):
            return
        with self.lock:
            target: Exchange | None = None
            if "method" not in message:
                target = (
                    self.waiting.pop(message.get("id"), None)
                    if valid_id(message.get("id"))
                    else None
                )
                if target is None:
                    return  # A response nobody waits for (its client went away)
            else:
                params = message.get("params")
                token = params.get("progressToken") if isinstance(params, dict) else None
                if message.get("method") == "notifications/progress" and token is not None:
                    target = self.progress.get(token) if isinstance(token, str | int) else None
                if target is None:
                    target = self.get_stream
                if target is None:
                    live = [e for e in self.waiting.values() if e.out.mode != "done"]
                    target = live[-1] if live else None
                if target is None:
                    self.buffered.append((text, message))
                    del self.buffered[:-MAX_BUFFERED]
                    return
        target.actions.put(("message", text, message))

    def open_get(self, exchange: Exchange) -> int:
        """Attach a GET stream to the current session; return an HTTP status to refuse it."""
        with self.lock:
            if self.get_stream is not None:
                return 409
            self.get_stream = exchange
            for text, message in self.buffered:
                exchange.actions.put(("message", text, message))
            self.buffered.clear()
        return 0

    def end_session(self, session_id: str) -> bool:
        with self.lock:
            if session_id != self.session_id:
                return False
            self._end_locked()
            return True


# --------------------------------------------------------------------------- HTTP front


class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler of the proxy endpoint."""

    protocol_version = "HTTP/1.1"
    server_version = "toolguard"
    sys_version = ""
    timeout = CLIENT_TIMEOUT
    server: _Server

    def log_message(self, format: str, *args: Any) -> None:
        """Do not log requests: their lines and headers may carry credentials."""

    # ---------------------------------------------------------------- helpers

    @property
    def front(self) -> HttpProxy:
        return self.server.front

    def plain(self, status: int, message: Any = None, headers: list[tuple[str, str]] = ()) -> None:
        """Answer with a complete response written by the proxy.

        If the request body was not read, the connection is closed afterwards: its
        bytes would otherwise be parsed as the next request.
        """
        if not getattr(self, "consumed", True):
            headers = [*headers, ("Connection", "close")]
            self.close_connection = True
        out = ClientResponse(self)
        with contextlib.suppress(ClientGone):
            if message is None:
                out.body(status, b"", headers)
            else:
                out.json(message, status, headers)

    def _note_body(self) -> None:
        """Remember whether the request carries a body that has not been read yet."""
        coding = (self.headers.get("Transfer-Encoding") or "").lower()
        length = self.headers.get("Content-Length")
        self.consumed = coding in ("", "identity") and length in (None, "0")

    def _lower_headers(self) -> dict[str, str]:
        return {name.lower(): value for name, value in self.headers.items()}

    def _admit(self) -> bool:
        """Check path, Host and Origin; answer and return ``False`` if refused."""
        self._note_body()
        front = self.front
        path = self.path.split("?", 1)[0]
        if path != front.path:
            self.plain(404, error(None, INVALID_REQUEST, "Not Found"))
            return False
        host = (self.headers.get("Host") or "").strip().lower()
        if host not in front.allowed_hosts:
            front.audit_rejection(self.command, "host", host)
            self.plain(421, error(None, INVALID_REQUEST, "Invalid Host header"))
            return False
        origin = self.headers.get("Origin")
        if origin is not None and not front.origin_allowed(origin):
            front.audit_rejection(self.command, "origin", origin)
            self.plain(403, error(None, INVALID_REQUEST, "Invalid Origin header"))
            return False
        return True

    def _read_body(self) -> bytes | None:
        if (self.headers.get("Transfer-Encoding") or "").lower() not in ("", "identity"):
            if (self.headers.get("Transfer-Encoding") or "").lower() != "chunked":
                self.plain(501, error(None, INVALID_REQUEST, "Unsupported transfer coding"))
                return None
            return self._read_chunked()
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = -1
        if length < 0:
            self.plain(400, error(None, INVALID_REQUEST, "Invalid Content-Length"))
            return None
        if length > self.front.max_body:
            self.close_connection = True
            self.plain(413, error(None, INVALID_REQUEST, "Request body too large"))
            return None
        data = self.rfile.read(length)
        if len(data) < length:
            self.close_connection = True
            return None
        self.consumed = True
        return data

    def _read_chunked(self) -> bytes | None:
        data = b""
        while True:
            line = self.rfile.readline(1024)
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                self.close_connection = True
                self.plain(400, error(None, INVALID_REQUEST, "Invalid chunked body"))
                return None
            if size == 0:
                while self.rfile.readline(1024).strip():
                    pass  # Trailers
                self.consumed = True
                return data
            if len(data) + size > self.front.max_body:
                self.close_connection = True
                self.plain(413, error(None, INVALID_REQUEST, "Request body too large"))
                return None
            data += self.rfile.read(size)
            self.rfile.readline(1024)

    # ---------------------------------------------------------------- methods

    def do_POST(self) -> None:
        """Guard one client message and forward it, answer it or accept it."""
        if not self._admit():
            return
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self.plain(415, error(None, INVALID_REQUEST, "Content-Type must be application/json"))
            return
        body = self._read_body()
        if body is None:
            return
        try:
            text, raw = body.decode("utf-8"), body
        except UnicodeDecodeError:
            text, raw = body.decode("utf-8", "replace"), None
        message = _parse(text)
        if message is _UNPARSED:
            self.plain(400, error(None, PARSE_ERROR, "Parse error"))
            return
        if isinstance(message, list):
            self.plain(400, error(None, INVALID_REQUEST, "Batches are not supported"))
            return
        headers = self._lower_headers()
        if isinstance(message, dict) and isinstance(message.get("method"), str):
            reason = header_mismatch(message, headers)
            if reason is not None:
                self.plain(400, error(message.get("id"), HEADER_MISMATCH, reason))
                return
        self.front.post(self, message, raw, headers)

    def do_GET(self) -> None:
        """Open (or resume) the server's SSE stream."""
        if self._admit() and (self.consumed or self._read_body() is not None):
            self.front.get(self, self._lower_headers())

    def do_DELETE(self) -> None:
        """End the session."""
        if self._admit() and (self.consumed or self._read_body() is not None):
            self.front.delete(self, self._lower_headers())

    def _not_allowed(self) -> None:
        self._note_body()
        self.plain(405, None, [("Allow", "GET, POST, DELETE")])

    do_PUT = do_PATCH = do_HEAD = do_OPTIONS = _not_allowed


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    front: HttpProxy

    def __init__(self, address: tuple[str, int], front: HttpProxy) -> None:
        self.front = front
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, ProxyHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.slots.acquire(blocking=False):
            with contextlib.suppress(OSError):
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Stay quiet when a client hangs up; tracebacks could show request data."""

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class HttpProxy:
    """Serve the guarded MCP endpoint over Streamable HTTP."""

    def __init__(
        self,
        guard: Guard,
        server_name: str,
        *,
        upstream: str | None = None,
        command: list[str] | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        path: str = DEFAULT_PATH,
        allowed_hosts: list[str] | None = None,
        allowed_origins: list[str] | None = None,
        max_body: int = MAX_BODY,
        timeout: float = UPSTREAM_TIMEOUT,
        elicitation_timeout: float = ELICITATION_TIMEOUT,
        shutdown_grace: float = SHUTDOWN_GRACE,
        queue: QueueApprover | None = None,
        popen: Callable[..., Any] | None = None,
        context: ssl.SSLContext | None = None,
    ) -> None:
        if (upstream is None) == (command is None):
            raise ValueError("give either an upstream URL or a server command")
        self.core = GuardCore(
            guard, server_name, queue=queue, elicitation_timeout=elicitation_timeout
        )
        self.path = path if path.startswith("/") else f"/{path}"
        self.max_body = max_body
        self.server = _Server((host, port), self)
        self.port = self.server.server_address[1]
        self.host = host
        names = LOOPBACK_NAMES if is_loopback(host) else (f"[{host}]" if ":" in host else host,)
        self.allowed_hosts = {f"{name}:{self.port}" for name in names}
        self.allowed_hosts.update(h.lower() for h in allowed_hosts or ())
        self.allowed_origins = [o.lower().rstrip("/") for o in allowed_origins or ()]
        self.backend: UpstreamBackend | StdioBackend
        if upstream is not None:
            self.backend = UpstreamBackend(
                self, Upstream(upstream, timeout=timeout, context=context)
            )
        else:
            self.backend = StdioBackend(
                self, list(command or ()), shutdown_grace=shutdown_grace, popen=popen
            )

    @property
    def guard(self) -> Guard:
        """The guard that decides on calls and records observations."""
        return self.core.guard

    @property
    def url(self) -> str:
        """The endpoint URL clients connect to."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}{self.path}"

    # ---------------------------------------------------------------- policy

    def origin_allowed(self, origin: str) -> bool:
        """Return whether a browser page at ``origin`` may call the proxy.

        Loopback pages (any port) are allowed, as the SDK servers allow them by
        default; other origins only when listed with ``--allow-origin``.
        """
        value = origin.strip().lower().rstrip("/")
        if value in self.allowed_origins:
            return True
        parts = urlsplit(value)
        try:
            host = parts.hostname
        except ValueError:
            return False
        return parts.scheme in ("http", "https") and host is not None and is_loopback(host)

    def audit_rejection(self, method: str, reason: str, value: str) -> None:
        """Record a refused request (a DNS-rebinding attempt looks like this)."""
        self.guard.audit.append(
            "transport",
            self.guard.session,
            {
                "integration": "mcp-proxy",
                "server": self.core.server_name,
                "outcome": "rejected",
                "reason": reason,
                "method": method,
                reason: value[:200],
            },
        )

    # ---------------------------------------------------------------- tracking

    def track(self, state: ClientState, request_id: Any, tracked: Tracked) -> None:
        """Remember a forwarded request until its response is seen on any stream."""
        with state.lock:
            state.calls[request_id] = tracked
            while len(state.calls) > MAX_TRACKED:
                state.calls.pop(next(iter(state.calls)))

    def untrack(self, state: ClientState, request_id: Any, mine: Tracked | None) -> Tracked | None:
        """Forget a request whose response arrived; return what was tracked for its id.

        ``mine`` is the exchange's own entry: an entry with the same id from another
        client of a session-less server is left alone.
        """
        with state.lock:
            entry = state.calls.get(request_id)
            if entry is not None and (mine is None or entry is mine):
                del state.calls[request_id]
                return entry
        return None

    def session_headers(self, exchange: Exchange) -> list[tuple[str, str]]:
        """Headers of a response written by the proxy itself (stdio mode)."""
        if exchange.session_id is not None:
            return [("Mcp-Session-Id", exchange.session_id)]
        return []

    # ---------------------------------------------------------------- requests

    def post(
        self, handler: ProxyHandler, message: Any, raw: bytes | None, headers: dict[str, str]
    ) -> None:
        backend = self.backend
        if isinstance(backend, UpstreamBackend):
            session_id = headers.get(SESSION)
            state = backend.state_for(session_id, message)
        else:
            state, session_id, status, reason = backend.state_for(headers, message)
            if state is None:
                handler.plain(status, error(None, INVALID_REQUEST, reason))
                return
        exchange = Exchange(self, handler, state, message, session_id)
        if session_id is not None and not isinstance(backend, UpstreamBackend):
            exchange.out.headers.append(("Mcp-Session-Id", session_id))
        self.core.handle(message, raw, state, exchange)
        exchange.run()

    def get(self, handler: ProxyHandler, headers: dict[str, str]) -> None:
        backend = self.backend
        if isinstance(backend, UpstreamBackend):
            session_id = headers.get(SESSION)
            exchange = Exchange(
                self, handler, backend.state_for(session_id, None), None, session_id
            )
            try:
                backend.get(exchange)
            except ClientGone:
                pass
            finally:
                if exchange.reader is not None:
                    exchange.reader.close()
            return
        if "text/event-stream" not in (headers.get("accept") or ""):
            handler.plain(
                406, error(None, INVALID_REQUEST, "Accept must include text/event-stream")
            )
            return
        session_id = headers.get(SESSION)
        if backend.session_id is None:
            handler.plain(405, None, [("Allow", "POST")])
            return
        if session_id is None:
            handler.plain(400, error(None, INVALID_REQUEST, "Mcp-Session-Id header is required"))
            return
        if session_id != backend.session_id:
            handler.plain(404, error(None, INVALID_REQUEST, "Session not found"))
            return
        exchange = Exchange(self, handler, backend.state, None, session_id)
        status = backend.open_get(exchange)
        if status:
            handler.plain(status, error(None, INVALID_REQUEST, "Only one GET stream per session"))
            return
        try:
            exchange.out.start_sse(200, [("Mcp-Session-Id", session_id)])
            while exchange.out.mode == "sse":
                try:
                    action = exchange.actions.get(timeout=KEEPALIVE)
                except queue.Empty:
                    exchange.out.ping()
                    continue
                exchange._do(action)
        except ClientGone:
            pass
        finally:
            backend.release(exchange)

    def delete(self, handler: ProxyHandler, headers: dict[str, str]) -> None:
        backend = self.backend
        session_id = headers.get(SESSION)
        if isinstance(backend, UpstreamBackend):
            exchange = Exchange(
                self, handler, backend.state_for(session_id, None), None, session_id
            )
            try:
                backend.delete(exchange)
            except ClientGone:
                pass
            finally:
                if exchange.reader is not None:
                    exchange.reader.close()
            return
        if session_id is None:
            handler.plain(400, error(None, INVALID_REQUEST, "Mcp-Session-Id header is required"))
        elif backend.end_session(session_id):
            handler.plain(200)
        else:
            handler.plain(404, error(None, INVALID_REQUEST, "Session not found"))

    # ---------------------------------------------------------------- lifetime

    def serve(self) -> None:
        """Serve requests until :meth:`shutdown` is called."""
        self.server.serve_forever(poll_interval=0.2)

    def shutdown(self) -> None:
        """Stop serving and close the listening socket."""
        self.server.shutdown()
        self.server.server_close()

    def run(self, announce: Callable[[str], None] | None = None) -> int:
        """Serve until interrupted (upstream mode) or until the server exits (stdio mode)."""
        backend = self.backend
        if announce is not None:
            announce(self.url)
        if isinstance(backend, UpstreamBackend):
            try:
                self.serve()
            except KeyboardInterrupt:
                pass
            finally:
                self.server.server_close()
            return 0
        process = backend.start_server()
        pump = threading.Thread(target=backend._pump_server, daemon=True)
        pump.start()
        serving = threading.Thread(target=self.serve, daemon=True)
        serving.start()
        try:
            code = process.wait()
        except KeyboardInterrupt:
            backend.stop_server()
            code = process.wait()
        pump.join(backend.shutdown_grace)
        self.shutdown()
        return code


def announce_to_stderr(url: str) -> None:
    """Tell the operator where the proxy listens."""
    print(f"toolguard: MCP proxy listening on {url}", file=sys.stderr, flush=True)
