"""MCP stdio proxy that guards ``tools/call`` requests between a client and a server.

The guard itself lives in :mod:`.mcp_core` (see there for what is evaluated and
observed); this module is its stdio transport: newline-delimited JSON-RPC on the
proxy's stdin and stdout, relayed to a server process. Proxies that share a
``--session`` and state directory share taint, so data read through one server is
tracked when it reaches another.

The proxy only forwards what it has inspected: client lines that are not JSON are
answered with a parse error instead of being relayed, batches are split and each
message is handled on its own, and a ``tools/call`` it cannot evaluate is refused.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import IO, Any

from ..approvals import QueueApprover
from ..guard import Guard
from .mcp_core import (
    ELICITATION_TIMEOUT,
    INVALID_REQUEST,
    PARSE_ERROR,
    ClientState,
    GuardCore,
    Tracked,
    error,
    valid_id,
)

SHUTDOWN_GRACE = 5.0  # Seconds the server gets to exit at each step of the shutdown


class StdioServer:
    """A server process spoken to over stdio, with the MCP stdio shutdown sequence."""

    def __init__(
        self,
        command: list[str],
        *,
        shutdown_grace: float = SHUTDOWN_GRACE,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    ) -> None:
        self.command = command
        self.shutdown_grace = shutdown_grace
        self.popen = popen
        self.server: subprocess.Popen[bytes] | None = None
        self._in_lock = threading.Lock()
        self._stop_lock = threading.Lock()
        self._stopping = False

    def resolve_command(self) -> list[str]:
        """Return the server command with its program resolved on ``PATH``.

        On Windows this finds launchers such as ``npx.cmd`` that ``CreateProcess``
        does not look up by bare name.
        """
        command = list(self.command)
        if command:
            command[0] = shutil.which(command[0]) or command[0]
        return command

    def start_server(self) -> subprocess.Popen[bytes]:
        """Start the server process with piped stdin and stdout."""
        self.server = self.popen(
            self.resolve_command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )
        return self.server

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

    def _pump_server(self) -> None:
        if self.server is None or self.server.stdout is None:
            raise RuntimeError("the MCP server is not running")
        for line in self.server.stdout:
            if line.strip():
                self.handle_server_line(line)

    def handle_server_line(self, line: bytes) -> None:  # pragma: no cover - overridden
        """Handle one line written by the server."""
        raise NotImplementedError

    def stop_server(self) -> None:
        """Close the server's stdin, then terminate and kill it if it does not exit.

        This is the stdio shutdown sequence of the MCP specification; without it a
        server that keeps timers running would outlive its client.
        """
        server = self.server
        with self._stop_lock:
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


class McpProxy(StdioServer):
    """Relay JSON-RPC lines between a client and a server, guarding what reaches either."""

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
        super().__init__(command, shutdown_grace=shutdown_grace, popen=popen)
        self.core = GuardCore(
            guard, server_name, queue=queue, elicitation_timeout=elicitation_timeout
        )
        self.state = ClientState()
        self.client_in = client_in or sys.stdin.buffer
        self.client_out = client_out or sys.stdout.buffer
        self._out_lock = threading.Lock()
        self._client_gone = False

    @property
    def guard(self) -> Guard:
        """The guard that decides on calls and records observations."""
        return self.core.guard

    @property
    def server_name(self) -> str:
        """The name used in ``mcp__<server-name>__<tool>``."""
        return self.core.server_name

    @property
    def client_elicitation(self) -> bool:
        """Whether the client declared form-mode elicitation in ``initialize``."""
        return self.state.elicitation

    @property
    def _calls(self) -> dict[Any, Tracked]:
        return self.state.calls

    # ------------------------------------------------------------------ Peer

    def reply(self, message: dict[str, Any]) -> None:
        """Send a message written by the proxy to the client."""
        self._write_client((json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8"))

    def forward(self, message: Any, raw: bytes | None, tracked: Tracked | None) -> None:
        """Send a client message to the server, as received when it was valid UTF-8."""
        if tracked is not None and isinstance(message, dict):
            with self.state.lock:
                self.state.calls[message["id"]] = tracked
        if raw is not None:
            self._send_server_raw(raw)
        else:
            self._send_server(message)

    def drop(self) -> None:
        """Nothing to release: a dropped request just gets no line."""

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

    # ------------------------------------------------------------------ main loop

    def run(self) -> int:
        """Start the server, relay messages until it exits and return its exit code."""
        server = self.start_server()
        server_pump = threading.Thread(target=self._pump_server, daemon=True)
        server_pump.start()
        threading.Thread(target=self._pump_client, daemon=True).start()
        code = server.wait()
        server_pump.join(self.shutdown_grace)  # Relay what the server wrote before exiting
        return code

    def _pump_client(self) -> None:
        for line in self.client_in:
            if line.strip():
                self.handle_client_line(line)
        self.stop_server()

    # ------------------------------------------------------------------ client -> server

    def handle_client_line(self, line: bytes) -> None:
        """Guard each message of a client line and relay it, answer it or drop it.

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
            self.reply(error(None, PARSE_ERROR, "Parse error"))
            return
        if isinstance(message, list):
            # A JSON-RPC batch (allowed before protocol 2025-06-18): handle each message.
            if not message:
                self.reply(error(None, INVALID_REQUEST, "Invalid Request"))
            for item in message:
                self.core.handle(item, None, self.state, self)
            return
        self.core.handle(message, line if exact else None, self.state, self)

    # ------------------------------------------------------------------ server -> client

    def handle_server_line(self, line: bytes) -> None:
        """Relay a server message, recording the results of forwarded source calls."""
        try:
            # Decode as a tolerant client would, so what it reads is what gets observed.
            message = json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            message = None
        if isinstance(message, dict) and "method" not in message:
            request_id = message.get("id")
            if valid_id(request_id):
                with self.state.lock:
                    tracked = self.state.calls.pop(request_id, None)
                if tracked is not None:
                    self.core.observe(tracked, message, self.state)
        self._write_client(line if line.endswith(b"\n") else line + b"\n")
