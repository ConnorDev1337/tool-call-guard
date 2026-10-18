"""Relay TCP connections to a target port and record every byte in both directions.

Usage: ``python tcptap.py LOG LISTEN_PORT TARGET_PORT``

The tap listens on ``127.0.0.1:LISTEN_PORT`` and relays each connection to
``127.0.0.1:TARGET_PORT``. Each chunk goes to LOG as one JSON object: ``t``
(``CLOCK_MONOTONIC`` seconds, shared by all processes on the host, so the logs of
several taps can be merged), ``conn`` (a connection number), ``dir`` (``up`` for
bytes from the connecting side, ``down`` for bytes back to it, ``open`` and
``close``) and ``b64`` (the bytes). The tap prints ``ready`` once it listens.
"""

from __future__ import annotations

import base64
import contextlib
import itertools
import json
import socket
import sys
import threading
import time


class TcpTap:
    """Accept connections and relay them, logging each chunk with the shared clock."""

    def __init__(self, log_path: str, listen: int, target: int) -> None:
        self.log = open(log_path, "a", encoding="utf-8")  # noqa: SIM115
        self.lock = threading.Lock()
        self.target = target
        self.ids = itertools.count(1)
        self.server = socket.create_server(("127.0.0.1", listen))

    def record(self, conn: int, direction: str, data: bytes = b"") -> None:
        entry = {"t": round(time.monotonic(), 6), "conn": conn, "dir": direction}
        if data:
            entry["b64"] = base64.b64encode(data).decode("ascii")
        with self.lock:
            self.log.write(json.dumps(entry) + "\n")
            self.log.flush()

    def pump(self, conn: int, source: socket.socket, target: socket.socket, direction: str):
        try:
            while data := source.recv(65536):
                self.record(conn, direction, data)
                target.sendall(data)
        except OSError:
            pass
        finally:
            # Pass the half-close on, as a proxy that ends a stream does.
            with contextlib.suppress(OSError):
                target.shutdown(socket.SHUT_WR)

    def handle(self, client: socket.socket) -> None:
        conn = next(self.ids)
        try:
            upstream = socket.create_connection(("127.0.0.1", self.target))
        except OSError:
            client.close()
            return
        self.record(conn, "open")
        down = threading.Thread(target=self.pump, args=(conn, upstream, client, "down"))
        down.start()
        self.pump(conn, client, upstream, "up")
        down.join()
        self.record(conn, "close")
        client.close()
        upstream.close()

    def run(self) -> None:
        print("ready", flush=True)
        while True:
            client, _ = self.server.accept()
            threading.Thread(target=self.handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    TcpTap(sys.argv[1], int(sys.argv[2]), int(sys.argv[3])).run()
