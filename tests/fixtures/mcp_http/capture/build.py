"""Turn the driver's tap logs into replay fixtures (see ../README.md).

Usage: ``python build.py OUT_DIR TARGET_DIR``

The TCP taps logged raw bytes per connection; this script parses them as HTTP/1.1
(requests, responses, chunked bodies and server-sent events) and merges the client
side, the upstream side and, for the stdio front, the stdio tap into one transcript
per scenario, ordered by the shared monotonic clock. Directions are ``c2p`` (client
to proxy), ``p2c``, ``p2u`` (proxy to upstream), ``u2p``, ``p2s`` and ``s2p`` (stdio).
Hidden characters are written as escapes, and the build fails if a transcript
names the capture host.
"""

from __future__ import annotations

import base64
import contextlib
import getpass
import json
import os
import sys
import unicodedata
from pathlib import Path
from typing import Any

SIDES = {"client": ("c2p", "p2c"), "upstream": ("p2u", "u2p")}
STDIO = {"in": "p2s", "out": "s2p"}


def forbidden_words() -> tuple[str, ...]:
    """Return strings that identify the capture machine: user, host and checkout paths."""
    words = {"C:" + chr(92) + "Users", "/Users/", str(Path.home()), Path.home().as_posix()}
    checkouts = Path(__file__).resolve().parents[5]  # The directory holding the checkout
    words.update(part for part in checkouts.parts if part.isalnum() and len(part) >= 4)
    with contextlib.suppress(KeyError, OSError):  # No user entry; the paths still apply
        words.add(getpass.getuser())
    words.update(os.environ.get(key, "") for key in ("USERNAME", "USER", "COMPUTERNAME"))
    return tuple(sorted(word for word in words if len(word) >= 3))


def escape_hidden(text: str) -> str:
    """Replace hidden characters of a JSON document by JSON escapes."""
    out = []
    for ch in text:
        if ch not in "\n\t\r" and unicodedata.category(ch) in {"Cc", "Cf", "Co", "Zl", "Zp"}:
            data = ch.encode("utf-16-be")
            out.extend(
                chr(92) + "u" + format(int.from_bytes(data[i : i + 2]), "04x")
                for i in range(0, len(data), 2)
            )
        else:
            out.append(ch)
    return "".join(out)


def text_or_b64(data: bytes) -> dict[str, str]:
    try:
        return {"body": data.decode("utf-8")}
    except UnicodeDecodeError:
        return {"b64": base64.b64encode(data).decode("ascii")}


class Stream:
    """The bytes of one direction of a connection, with the time each arrived."""

    def __init__(self) -> None:
        self.data = b""
        self.times: list[tuple[int, float]] = []  # (end offset, time)
        self.pos = 0
        self.eof: float | None = None

    def add(self, chunk: bytes, t: float) -> None:
        self.data += chunk
        self.times.append((len(self.data), t))

    def time_at(self, offset: int) -> float:
        """Return when the byte before ``offset`` arrived."""
        for end, t in self.times:
            if end >= offset:
                return t
        return self.times[-1][1] if self.times else 0.0

    def find(self, marker: bytes) -> int:
        return self.data.find(marker, self.pos)

    def take(self, size: int) -> bytes | None:
        if self.pos + size > len(self.data):
            return None
        chunk = self.data[self.pos : self.pos + size]
        self.pos += size
        return chunk

    def line(self) -> bytes | None:
        end = self.find(b"\r\n")
        if end < 0:
            return None
        chunk = self.data[self.pos : end]
        self.pos = end + 2
        return chunk


def parse_head(stream: Stream) -> tuple[str, list[list[str]]] | None:
    end = stream.find(b"\r\n\r\n")
    if end < 0:
        return None
    head = stream.data[stream.pos : end].decode("latin-1")
    stream.pos = end + 4
    first, *lines = head.split("\r\n")
    headers = [[name, value.strip()] for name, _, value in (h.partition(":") for h in lines)]
    return first, headers


def header(headers: list[list[str]], name: str) -> str:
    return next((v for n, v in headers if n.lower() == name), "")


def body_units(stream: Stream, headers: list[list[str]], base: dict[str, Any]) -> list[dict]:
    """Parse one message body; return its units (events or a body, then ``end``)."""
    units: list[dict[str, Any]] = []
    sse = header(headers, "content-type").split(";")[0].strip() == "text/event-stream"
    if header(headers, "transfer-encoding").lower() == "chunked":
        pending = b""
        while True:
            size_line = stream.line()
            if size_line is None:
                return [*units, {**base, "abort": True}] if stream.eof is not None else units
            size = int(size_line.split(b";")[0], 16)
            if size == 0:
                stream.line()  # The CRLF after the last chunk
                t = stream.time_at(stream.pos)
                if not sse:
                    units.append({**base, "t": t, **text_or_b64(pending)})
                units.append({**base, "t": t, "end": True})
                return units
            chunk = stream.take(size + 2)
            if chunk is None:
                return [*units, {**base, "abort": True}]
            t = stream.time_at(stream.pos)
            pending += chunk[:-2]
            if sse:
                events, pending = sse_events(pending)
                units.extend({**base, "t": t, **event} for event in events)
    length = int(header(headers, "content-length") or 0)
    data = stream.take(length)
    if data is None:
        return [{**base, "abort": True}]
    t = stream.time_at(stream.pos)
    return [{**base, "t": t, **text_or_b64(data)}, {**base, "t": t, "end": True}]


def sse_events(data: bytes) -> tuple[list[dict[str, Any]], bytes]:
    """Split complete SSE blocks off ``data`` (the proxy and the servers use LF or CRLF)."""
    text = data.replace(b"\r\n", b"\n")
    events = []
    while b"\n\n" in text:
        block, text = text.split(b"\n\n", 1)
        event: dict[str, Any] = {}
        data_lines = []
        for line in block.decode("utf-8", "replace").split("\n"):
            if line.startswith(":"):
                event["comment"] = line[1:].strip()
                continue
            name, _, value = line.partition(":")
            value = value.removeprefix(" ")
            if name == "data":
                data_lines.append(value)
            elif name in ("id", "event", "retry"):
                event[name] = value
        if data_lines:
            event["data"] = "\n".join(data_lines)
        events.append({"event": event})
    return events, text


def parse_connection(side: str, conn: int, up: Stream, down: Stream) -> list[dict[str, Any]]:
    c2p, p2c = SIDES[side]
    units: list[dict[str, Any]] = []
    seq = 0
    while True:
        head = parse_head(up)
        if head is None:
            break
        first, headers = head
        method, target, _ = first.split(" ", 2)
        base = {"dir": c2p, "conn": conn, "seq": seq}
        request = body_units(up, headers, base)
        body = next((u for u in request if "body" in u or "b64" in u), {})
        units.append(
            {
                **base,
                "t": request[0].get("t", up.time_at(up.pos)) if request else up.time_at(up.pos),
                "request": {
                    "method": method,
                    "target": target,
                    "headers": headers,
                    **{k: body[k] for k in ("body", "b64") if k in body},
                },
            }
        )
        seq += 1
    seq = 0
    while True:
        head = parse_head(down)
        if head is None:
            break
        first, headers = head
        status = int(first.split(" ", 2)[1])
        base = {"dir": p2c, "conn": conn, "seq": seq}
        units.append(
            {
                **base,
                "t": down.time_at(down.pos),
                "response": {"status": status, "headers": headers},
            }
        )
        units.extend(body_units(down, headers, base))
        seq += 1
    for stream, direction in ((up, c2p), (down, p2c)):
        if stream.eof is not None:
            units.append({"t": stream.eof, "dir": direction, "conn": conn, "eof": True})
    return units


def read_tcp(path: Path, side: str) -> list[dict[str, Any]]:
    streams: dict[int, tuple[Stream, Stream]] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        entry = json.loads(raw)
        up, down = streams.setdefault(entry["conn"], (Stream(), Stream()))
        if entry["dir"] in ("up", "down"):
            (up if entry["dir"] == "up" else down).add(base64.b64decode(entry["b64"]), entry["t"])
        elif entry["dir"] == "eof-up":
            up.eof = entry["t"]
        elif entry["dir"] == "eof-down":
            down.eof = entry["t"]
    units = []
    for conn, (up, down) in streams.items():
        units.extend(parse_connection(side, conn, up, down))
    return units


def read_stdio(path: Path) -> list[dict[str, Any]]:
    events = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        entry = json.loads(raw)
        if entry["dir"] in STDIO:
            event = {"t": entry["t"], "dir": STDIO[entry["dir"]]}
            event |= {k: entry[k] for k in ("line", "b64") if k in entry}
            events.append(event)
    return events


def build(out_dir: Path, target: Path) -> None:
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    host = summary["versions"].pop("hostname", None)
    if not all(e["ok"] for e in summary["entries"]):
        raise SystemExit("some scenarios failed; not building fixtures")
    index: dict[str, Any] = {"versions": summary["versions"], "scenarios": {}}
    for entry in summary["entries"]:
        name = entry["scenario"]
        result = dict(entry["result"])
        setup = result.pop("setup", [])
        index["scenarios"][name] = {"seconds": entry["seconds"], "observed": result}
        events = read_tcp(out_dir / f"{name}.client.jsonl", "client")
        stdio = out_dir / f"{name}.server.jsonl"
        if stdio.exists():
            events += read_stdio(stdio)
        else:
            events += read_tcp(out_dir / f"{name}.upstream.jsonl", "upstream")
        events.sort(key=lambda e: e["t"])
        start = events[0]["t"]
        for event in events:
            event["t"] = round(event["t"] - start, 4)
        fixture = {
            "scenario": name,
            "transport": "http-stdio" if stdio.exists() else "http-upstream",
            "server_name": entry["server"],
            "policy": "balanced",
            "setup": setup,
            "observed": result,
            "events": events,
        }
        text = escape_hidden(json.dumps(fixture, indent=1, ensure_ascii=False)) + "\n"
        assert json.loads(text) == fixture
        for word in (*forbidden_words(), *([host] if host else [])):
            if word in text:
                raise SystemExit(f"{name}: the transcript contains {word!r}")
        (target / f"{name}.json").write_text(text, encoding="utf-8", newline="\n")
        print(name, len(events), "events", len(text), "bytes")
    text = json.dumps(index, indent=2, ensure_ascii=False) + "\n"
    (target / "index.json").write_text(escape_hidden(text), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    build(Path(sys.argv[1]), Path(sys.argv[2]))
