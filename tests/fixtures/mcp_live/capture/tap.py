"""Run a stdio MCP process and record every line it reads and writes.

Usage: ``python tap.py LOG -- COMMAND [ARGS...]``

Each line goes to LOG as one JSON object: ``t`` (seconds since the tap started), ``dir``
(``in`` for lines read by the process, ``out`` for lines it wrote) and either ``line``
(UTF-8 text) or ``b64`` (bytes that are not valid UTF-8). SIGTERM and SIGINT are passed on
to the process, and the tap exits with its exit code.
"""

from __future__ import annotations

import base64
import json
import signal
import subprocess
import sys
import threading
import time
from typing import IO


class Tap:
    """Relay lines between this process's stdio and a child, logging both directions."""

    def __init__(self, log_path: str, command: list[str]) -> None:
        self.log = open(log_path, "a", encoding="utf-8")  # noqa: SIM115
        self.lock = threading.Lock()
        self.start = time.monotonic()
        self.child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def record(self, direction: str, line: bytes) -> None:
        entry: dict[str, object] = {"t": round(time.monotonic() - self.start, 6), "dir": direction}
        try:
            entry["line"] = line.decode("utf-8")
        except UnicodeDecodeError:
            entry["b64"] = base64.b64encode(line).decode("ascii")
        with self.lock:
            self.log.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self.log.flush()

    def pump(self, source: IO[bytes], target: IO[bytes] | None, direction: str) -> None:
        for line in iter(source.readline, b""):
            self.record(direction, line)
            if target is None:
                continue
            try:
                target.write(line)
                target.flush()
            except OSError:
                target = None  # The reader went away; keep draining and logging
        if direction == "in" and target is not None:
            try:
                target.close()
            except OSError:
                pass
            self.record("eof", b"")

    def run(self) -> int:
        child = self.child
        assert child.stdin is not None and child.stdout is not None
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda signum, _frame: child.send_signal(signum))
        threading.Thread(
            target=self.pump, args=(sys.stdin.buffer, child.stdin, "in"), daemon=True
        ).start()
        out = threading.Thread(target=self.pump, args=(child.stdout, sys.stdout.buffer, "out"))
        out.start()
        code = child.wait()
        out.join(10)
        self.record("exit", str(code).encode())
        return code


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] != "--":
        print(__doc__, file=sys.stderr)
        return 2
    return Tap(argv[0], argv[2:]).run()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
