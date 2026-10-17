"""Turn the driver's tap logs into replay fixtures (see ../README.md).

Usage: ``python build.py OUT_DIR TARGET_DIR``

For each scenario the client-side and server-side tap logs of every proxy are
merged into one transcript ordered by the shared monotonic clock. Directions are
``c2p`` (client to proxy), ``p2c``, ``p2s`` (proxy to server) and ``s2p``; ``oob``
marks the moment the human approved out of band. Lines are kept byte for byte
(``line``, or ``b64`` for bytes that are not UTF-8). Hidden characters are written
as ``\\uXXXX`` escapes, and the build fails if a line names the capture host.
"""

from __future__ import annotations

import ast
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any

DIRECTIONS = {("client", "in"): "c2p", ("client", "out"): "p2c"}
DIRECTIONS |= {("server", "in"): "p2s", ("server", "out"): "s2p"}
SKIP = {"large"}  # Megabytes of generated content; the summary is kept in index.json
FORBIDDEN = ("PROYECTOS", "CONNOR", "Connor", "C:\\Users", "/Users/", "parendum")


def escape_hidden(text: str) -> str:
    """Replace hidden characters of a JSON document by ``\\uXXXX`` escapes."""
    out = []
    for ch in text:
        if ch not in "\n\t\r" and unicodedata.category(ch) in {"Cc", "Cf", "Co", "Zl", "Zp"}:
            data = ch.encode("utf-16-be")
            out.extend(
                "\\u" + format(int.from_bytes(data[i : i + 2]), "04x")
                for i in range(0, len(data), 2)
            )
        else:
            out.append(ch)
    return "".join(out)


def task_policy() -> str:
    """Return the TASK_POLICY text of driver.py without importing it (it needs ``mcp``)."""
    tree = ast.parse((Path(__file__).parent / "driver.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "TASK_POLICY":
            return ast.literal_eval(node.value)
    raise SystemExit("TASK_POLICY not found in driver.py")


def read_log(path: Path, server: str | None, side: str | None) -> list[dict[str, Any]]:
    events = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        entry = json.loads(raw)
        if entry["dir"] == "oob":
            events.append({"t": entry["t"], "dir": "oob", "action": entry["line"]})
            continue
        if entry["dir"] in {"eof", "exit"}:
            event = {"t": entry["t"], "dir": f"{side}-{entry['dir']}", "server": server}
            if entry["dir"] == "exit":
                event["code"] = int(entry["line"])
            events.append(event)
            continue
        event = {"t": entry["t"], "dir": DIRECTIONS[side, entry["dir"]], "server": server}
        event |= {k: entry[k] for k in ("line", "b64") if k in entry}
        events.append(event)
    return events


def build(out_dir: Path, target: Path) -> None:
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    host = summary["versions"].pop("hostname", None)
    results = {e["scenario"]: e for e in summary["entries"]}
    if not all(e["ok"] for e in results.values()):
        raise SystemExit("some scenarios failed; not building fixtures")
    scenarios: dict[str, list[Path]] = {}
    for log in sorted(out_dir.glob("*.jsonl")):
        scenarios.setdefault(log.name.split("-", 1)[0], []).append(log)
    index: dict[str, Any] = {"versions": summary["versions"], "scenarios": {}}
    for name, logs in scenarios.items():
        key = "oob_queue" if name == "queue" else name
        entry = results[key]
        index["scenarios"][name] = {"seconds": entry["seconds"], "observed": entry["result"]}
        if name in SKIP:
            continue
        events = []
        for log in logs:
            stem = log.name.removesuffix(".jsonl")
            if stem.endswith("-oob"):
                events += read_log(log, None, None)
                continue
            server, side = stem.split("-", 1)[1].rsplit(".", 1)
            events += read_log(log, server, side)
        events.sort(key=lambda e: e["t"])
        start = events[0]["t"]
        for event in events:
            event["t"] = round(event["t"] - start, 4)
        fixture = {
            "scenario": name,
            "servers": sorted({e["server"] for e in events if e.get("server")}),
            "policy": task_policy() if name == "tasks" else "balanced",
            "observed": entry["result"],
            "events": events,
        }
        text = escape_hidden(json.dumps(fixture, indent=1, ensure_ascii=False)) + "\n"
        assert json.loads(text) == fixture
        for word in (*FORBIDDEN, *([host] if host else [])):
            if word in text:
                raise SystemExit(f"{name}: the transcript contains {word!r}")
        (target / f"{name}.json").write_text(text, encoding="utf-8", newline="\n")
        print(name, len(events), "events", len(text), "bytes")
    text = json.dumps(index, indent=2, ensure_ascii=False) + "\n"
    (target / "index.json").write_text(escape_hidden(text), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    build(Path(sys.argv[1]), Path(sys.argv[2]))
