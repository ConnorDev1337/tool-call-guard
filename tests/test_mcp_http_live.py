"""Replay Streamable HTTP traffic captured from real MCP servers behind the proxy.

The fixtures in ``fixtures/mcp_http`` were recorded with the official Python SDK
client and real servers in a throwaway container (see its README). Each replay runs
an in-process HTTP proxy between a scripted client and a scripted upstream (or stdio
server) and walks the transcript in its recorded order: it sends what the client and
the server sent, and waits for the proxy to write what it wrote, comparing each HTTP
response, server-sent event, body and upstream request. Random values the proxy
creates (elicitation ids, approval ids, the session ids of its stdio front) are mapped.
"""

import base64
import contextlib
import http.client
import json
import queue
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from conftest import FIXTURES
from toolguard.adapters import mcp_http
from toolguard.adapters.mcp_http import HttpProxy, SseParser

LIVE = FIXTURES / "mcp_http"
INDEX = json.loads((LIVE / "index.json").read_text(encoding="utf-8"))
SCENARIOS = sorted(p.stem for p in LIVE.glob("*.json") if p.stem != "index")
RANDOM = (re.compile(r"toolguard-[0-9a-f]{24}"), re.compile(r"(?<=approval )[0-9a-f]{8}\b"))
TIMEOUT = 10.0
# Headers that differ between runs for reasons unrelated to the proxy's behaviour.
VOLATILE = {"date", "host", "content-length"}


def load(name):
    return json.loads((LIVE / f"{name}.json").read_text(encoding="utf-8"))


def body_of(unit):
    if "b64" in unit:
        return base64.b64decode(unit["b64"]).decode("utf-8", "replace")
    return unit.get("body", "")


def same_json(recorded, replayed):
    try:
        return json.loads(recorded) == json.loads(replayed)
    except ValueError:
        return recorded == replayed


class Upstream:
    """Stands in for the recorded upstream server, answering only as the replay says."""

    def __init__(self):
        self.arrived = queue.Queue()  # (request, responder) as the proxy sends them
        self.stop = threading.Event()
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8") if length else None
                request = {
                    "method": self.command,
                    "target": self.path,
                    "headers": [[k, v] for k, v in self.headers.items()],
                    "body": body,
                }
                responder = Responder(self, upstream.stop)
                upstream.arrived.put((request, responder))
                responder.run()
                self.close_connection = True

            do_GET = do_POST = do_DELETE = _serve

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.handle_error = lambda request, address: None
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/mcp"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()


class Responder:
    """Writes one recorded upstream response, unit by unit, when told to."""

    def __init__(self, handler, stop):
        self.handler = handler
        self.stop = stop
        self.actions = queue.Queue()
        self.head = None

    def run(self):
        while not self.stop.is_set():
            try:
                unit = self.actions.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                if not self._write(unit):
                    return
            except OSError:
                return  # The proxy closed the connection

    def _write(self, unit):
        h = self.handler
        if "response" in unit:
            self.head = unit["response"]
            names = {n.lower(): v for n, v in self.head["headers"]}
            self.chunked = names.get("transfer-encoding", "").lower() == "chunked"
            if self.chunked:
                self._send_head(None)
            return True
        if "event" in unit:
            event = unit["event"]
            if "comment" in event and len(event) == 1:
                data = f": {event['comment']}\n\n".encode()
            else:
                fields = {k: event.get(k) for k in ("data", "event", "id", "retry")}
                data = mcp_http.SseEvent(**fields).encode()
            h.wfile.write(f"{len(data):X}\r\n".encode() + data + b"\r\n")
            h.wfile.flush()
            return True
        if "body" in unit or "b64" in unit:
            data = body_of(unit).encode("utf-8")
            if self.chunked:
                if data:
                    h.wfile.write(f"{len(data):X}\r\n".encode() + data + b"\r\n")
            else:
                self._send_head(len(data))
                h.wfile.write(data)
            h.wfile.flush()
            return True
        if unit.get("end"):
            if self.chunked:
                h.wfile.write(b"0\r\n\r\n")
                h.wfile.flush()
            return False
        return not unit.get("eof")

    def _send_head(self, length):
        h = self.handler
        h.send_response_only(self.head["status"])
        skip = {"content-length", "transfer-encoding", "connection", "date", "server"}
        for name, value in self.head["headers"]:
            if name.lower() not in skip:
                h.send_header(name, value)
        if length is None:
            h.send_header("Transfer-Encoding", "chunked")
        else:
            h.send_header("Content-Length", str(length))
        h.end_headers()


class ClientExchange:
    """One recorded client request, sent to the replayed proxy and read back."""

    def __init__(self, port, request):
        self.outputs = queue.Queue()
        self.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        self.done = False
        self.closed = False
        threading.Thread(target=self._run, args=(request,), daemon=True).start()

    def _run(self, request):
        try:
            has_body = "body" in request or "b64" in request
            body = body_of(request).encode("utf-8") if has_body else None
            self.conn.putrequest(
                request["method"], request["target"], skip_host=True, skip_accept_encoding=True
            )
            for name, value in request["headers"]:
                # A request recorded without its body (announced, never sent) keeps its length.
                if name.lower() != "content-length" or body is None:
                    self.conn.putheader(name, value)
            if body is not None:
                self.conn.putheader("Content-Length", str(len(body)))
            self.conn.endheaders(body)
            response = self.conn.getresponse()
            self.outputs.put(
                {
                    "response": {
                        "status": response.status,
                        "headers": [list(h) for h in response.getheaders()],
                    }
                }
            )
            if response.getheader("Content-Type", "").startswith("text/event-stream"):
                parser = SseParser()
                while chunk := response.read1(65536):
                    for event in parser.feed(chunk):
                        if event is None:
                            self.outputs.put({"event": {"comment": "keepalive"}})
                        else:
                            fields = event._asdict().items()
                            self.outputs.put({"event": {k: v for k, v in fields if v is not None}})
            else:
                self.outputs.put({"body": response.read().decode("utf-8", "replace")})
            self.outputs.put({"end": True})
        except (OSError, http.client.HTTPException, ValueError):
            self.outputs.put({"abort": True})
        finally:
            self.done = True
            self.conn.close()

    def close(self):
        """Hang up; the reader thread, which owns the connection, sees it and stops."""
        self.closed = True
        sock = self.conn.sock
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)


class FakeServer:
    """Stands in for the stdio server process of the stdio front."""

    def __init__(self):
        self.lines = []
        self.stdin = self

    def write(self, data):
        self.lines.append(bytes(data))

    def flush(self):
        pass


class Replay:
    """Runs one captured HTTP scenario through an in-process proxy."""

    def __init__(self, fixture, make_guard):
        self.fixture = fixture
        self.events = fixture["events"]
        self.guard = make_guard(fixture["policy"])
        for item in fixture.get("setup", []):
            self.guard.observe(item["tool"], item["content"], item["args"])
        # The proxy accepted the Host of every request it did not refuse with 421.
        refused = {
            (e["conn"], e["seq"])
            for e in self.events
            if e["dir"] == "p2c" and e.get("response", {}).get("status") == 421
        }
        hosts = {
            value
            for e in self.events
            if e["dir"] == "c2p" and "request" in e and (e["conn"], e["seq"]) not in refused
            for name, value in e["request"]["headers"]
            if name.lower() == "host"
        }
        kwargs = {"allowed_hosts": sorted(hosts)}
        self.upstream = None
        if fixture["transport"] == "http-upstream":
            self.upstream = Upstream()
            kwargs["upstream"] = self.upstream.url
        else:
            kwargs["command"] = ["unused"]
        self.proxy = HttpProxy(self.guard, fixture["server_name"], **kwargs)
        if self.upstream is None:
            self.proxy.backend.server = FakeServer()
        threading.Thread(target=self.proxy.serve, daemon=True).start()
        self.ids = {}  # Recorded random values -> replayed ones
        self.exchanges = {}  # (conn, seq) -> ClientExchange
        self.last = {}  # conn -> its latest exchange
        self.responders = {}  # upstream (conn, seq) -> Responder
        self.upstream_last = {}
        self.pending = []  # Upstream requests that arrived but are not matched yet
        self.stdio_seen = 0

    def close(self):
        for exchange in self.exchanges.values():
            exchange.close()
        self.proxy.shutdown()
        if self.upstream is not None:
            self.upstream.close()

    # ---------------------------------------------------------------- ids

    def _map(self, text):
        for old, new in self.ids.items():
            text = text.replace(old, new)
        return text

    def _learn(self, recorded, replayed):
        for pattern in RANDOM:
            old = list(dict.fromkeys(pattern.findall(recorded)))
            new = list(dict.fromkeys(pattern.findall(replayed)))
            for a, b in zip(old, new, strict=False):
                self.ids.setdefault(a, b)

    # ---------------------------------------------------------------- walking

    def run(self):
        for index, event in enumerate(self.events):
            where = f"event {index} ({event['dir']} conn {event.get('conn')})"
            direction = event["dir"]
            if direction == "c2p":
                self._client_sends(event)
            elif direction == "p2c":
                self._proxy_answers(event, where)
            elif direction == "p2u":
                self._proxy_asks_upstream(event, where)
            elif direction == "u2p":
                self._upstream_answers(event)
            elif direction == "s2p":
                line = event.get("line")
                data = line.encode("utf-8") if line is not None else base64.b64decode(event["b64"])
                self.proxy.backend.handle_server_line(data)
            elif direction == "p2s":
                self._proxy_tells_server(event, where)

    def _client_sends(self, event):
        if event.get("eof"):
            exchange = self.last.get(event["conn"])
            if exchange is not None and not exchange.done:
                exchange.close()  # The client hung up on a stream that was still open
            return
        request = json.loads(self._map(json.dumps(event["request"])))
        exchange = ClientExchange(self.proxy.port, request)
        self.exchanges[event["conn"], event["seq"]] = exchange
        self.last[event["conn"]] = exchange

    def _proxy_answers(self, event, where):
        if event.get("eof") or event.get("abort"):
            return  # Who closes first is timing, not behaviour
        exchange = self.exchanges[event["conn"], event["seq"]]
        if exchange.closed:
            return  # The client hung up: what the proxy wrote next went nowhere
        try:
            got = exchange.outputs.get(timeout=TIMEOUT)
        except queue.Empty:
            raise AssertionError(f"{where}: the proxy wrote nothing") from None
        while got.get("event") == {"comment": "keepalive"} and "comment" not in event.get(
            "event", {}
        ):
            got = exchange.outputs.get(timeout=TIMEOUT)  # Keepalives depend on timing
        if "response" in event:
            assert "response" in got, f"{where}: expected a response, got {got}"
            self._compare_response(event["response"], got["response"], where)
        elif "event" in event:
            assert "event" in got, f"{where}: expected an event, got {got}"
            self._compare_event(event["event"], got["event"], where)
        elif "body" in event or "b64" in event:
            assert "body" in got, f"{where}: expected a body, got {got}"
            recorded = body_of(event)
            self._learn(recorded, got["body"])
            assert same_json(self._map(recorded), got["body"]), f"{where}: body differs"
        elif event.get("end"):
            assert got.get("end"), f"{where}: expected the end, got {got}"

    def _compare_response(self, recorded, replayed, where):
        assert replayed["status"] == recorded["status"], f"{where}: status"
        old = {n.lower(): v for n, v in recorded["headers"] if n.lower() not in VOLATILE}
        new = {n.lower(): v for n, v in replayed["headers"] if n.lower() not in VOLATILE}
        session = old.get("mcp-session-id")
        if self.upstream is None and session and "mcp-session-id" in new:
            self.ids.setdefault(session, new["mcp-session-id"])  # Issued by the stdio front
        old = {k: self._map(v) for k, v in old.items()}
        assert new == old, f"{where}: headers differ"

    def _compare_event(self, recorded, replayed, where):
        if "data" in recorded and "data" in replayed:
            self._learn(recorded["data"], replayed["data"])
        recorded = {k: self._map(v) for k, v in recorded.items()}
        if "comment" in recorded:
            assert "comment" in replayed, f"{where}: expected a comment"
            return
        data_old, data_new = recorded.pop("data", None), replayed.pop("data", None)
        assert replayed == recorded, f"{where}: event fields differ"
        if data_old is None or data_new is None:
            assert data_old == data_new, f"{where}: event data"
        else:
            assert same_json(data_old, data_new), f"{where}: event data differs"

    def _proxy_asks_upstream(self, event, where):
        if event.get("eof"):
            return
        recorded = json.loads(self._map(json.dumps(event["request"])))
        deadline = TIMEOUT
        while True:
            match = next((p for p in self.pending if self._matches(recorded, p[0])), None)
            if match is not None:
                self.pending.remove(match)
                break
            try:
                self.pending.append(self.upstream.arrived.get(timeout=deadline))
            except queue.Empty:
                raise AssertionError(f"{where}: the proxy never sent {recorded}") from None
        request, responder = match
        old = {n.lower(): v for n, v in recorded["headers"] if n.lower() not in VOLATILE}
        new = {n.lower(): v for n, v in request["headers"] if n.lower() not in VOLATILE}
        assert new == old, f"{where}: upstream request headers differ"
        self.responders[event["conn"], event["seq"]] = responder
        self.upstream_last[event["conn"]] = responder

    @staticmethod
    def _matches(recorded, request):
        if (recorded["method"], recorded["target"]) != (request["method"], request["target"]):
            return False
        old = {n.lower(): v for n, v in recorded["headers"]}
        new = {n.lower(): v for n, v in request["headers"]}
        for name in ("mcp-session-id", "last-event-id"):
            if old.get(name) != new.get(name):
                return False
        recorded_body = body_of(recorded) if ("body" in recorded or "b64" in recorded) else None
        if recorded_body is None or request["body"] is None:
            return recorded_body == request["body"] or not (recorded_body or request["body"])
        return same_json(recorded_body, request["body"])

    def _upstream_answers(self, event):
        if event.get("eof"):
            responder = self.upstream_last.get(event["conn"])
        else:
            responder = self.responders.get((event["conn"], event["seq"]))
        if responder is not None:
            responder.actions.put(event)

    def _proxy_tells_server(self, event, where):
        lines = self.proxy.backend.server.lines
        deadline = threading.Event()
        for _ in range(int(TIMEOUT / 0.005)):
            if len(lines) > self.stdio_seen:
                break
            deadline.wait(0.005)
        else:
            raise AssertionError(f"{where}: the proxy never wrote to the server")
        got = lines[self.stdio_seen].decode("utf-8")
        self.stdio_seen += 1
        recorded = event.get("line") or base64.b64decode(event["b64"]).decode("utf-8", "replace")
        assert same_json(self._map(recorded), got), f"{where}: line sent to the server differs"


@pytest.fixture
def replay(make_guard):
    replays = []

    def _run(name):
        r = Replay(load(name), make_guard)
        replays.append(r)
        r.run()
        return r

    yield _run
    for r in replays:
        r.close()


def messages(events, direction):
    """Return the JSON-RPC messages of the bodies and events in one direction."""
    found = []
    for event in events:
        if event["dir"] != direction:
            continue
        if "request" in event and event["request"].get("body"):
            text = event["request"]["body"]
        elif "event" in event and event["event"].get("data"):
            text = event["event"]["data"]
        elif event.get("body"):
            text = event["body"]
        elif "line" in event:
            text = event["line"]
        else:
            continue
        try:
            found.append(json.loads(text))
        except ValueError:
            continue
    return found


def test_fixtures_are_sanitized_and_versioned():
    versions = INDEX["versions"]
    assert versions["mcp (client)"] == "2.3.0"
    assert versions["@modelcontextprotocol/server-everything"] == "1.0.0"
    assert "hostname" not in versions
    assert set(SCENARIOS) == set(INDEX["scenarios"])
    for name in SCENARIOS:
        text = (LIVE / f"{name}.json").read_text(encoding="utf-8")
        assert "C:\\\\Users" not in text and "/Users/" not in text


@pytest.mark.parametrize("name", SCENARIOS)
def test_replay_matches_the_recorded_traffic(replay, name):
    replay(name)


def test_credentials_pass_through_and_never_reach_the_audit(replay):
    r = replay("mail_legacy")
    for direction in ("c2p", "p2u"):
        auth = {
            value
            for e in r.events
            if e["dir"] == direction and "request" in e
            for name, value in e["request"]["headers"]
            if name.lower() == "authorization"
        }
        assert auth == {"Bearer placeholder-bearer-0123456789abcdef"}
    assert "placeholder-bearer" not in json.dumps(list(r.guard.audit.records()))
    upstream = [e for e in r.events if e["dir"] == "p2u" and "request" in e]
    assert all(
        name.lower() not in ("origin", "accept-encoding") or value == "identity"
        for e in upstream
        for name, value in e["request"]["headers"]
    )


def test_guard_decisions_over_http(replay):
    r = replay("mail_legacy")
    observed = r.fixture["observed"]
    assert observed["attacker"].startswith("toolguard: BLOCK")
    assert observed["refusals"][0].startswith("-32003 toolguard: BLOCK")
    assert observed["refusals"][1].startswith("-32003 toolguard: CONFIRM")
    tools = [o.tool for o in r.guard.store.observations("s1")]
    # The result of get_new_mail arrived on a resumed GET stream and is still observed.
    assert tools.count("mcp__mail__get_new_mail") == 1
    resumed = [
        e
        for e in r.events
        if e["dir"] == "c2p"
        and "request" in e
        and any(n.lower() == "last-event-id" for n, _ in e["request"]["headers"])
    ]
    assert len(resumed) == 1 and resumed[0]["request"]["method"] == "GET"
    asked = [m for m in messages(r.events, "p2c") if m.get("method") == "elicitation/create"]
    ours = [m for m in asked if str(m["id"]).startswith("toolguard-")]
    assert len(ours) == 3 and len(asked) == 4  # Three from the guard, one from the server
    sent = [m for m in messages(r.events, "p2u") if m.get("method") == "tools/call"]
    assert ["billing@evil-payments.example" not in json.dumps(m) for m in sent] == [True] * len(
        sent
    )


def test_stateless_revision_over_http(replay):
    r = replay("mail_modern")
    requests = [e["request"] for e in r.events if e["dir"] == "c2p" and "request" in e]
    versions = {
        value
        for q in requests
        for name, value in q["headers"]
        if name.lower() == "mcp-protocol-version"
    }
    assert versions == {"2026-07-28"}
    assert not any(n.lower() == "mcp-session-id" for q in requests for n, _ in q["headers"])
    names = [v for q in requests for n, v in q["headers"] if n.lower() == "mcp-name"]
    assert "read_inbox" in names
    refusal = next(m for m in messages(r.events, "p2c") if "toolguard: BLOCK" in json.dumps(m))
    assert refusal["result"]["resultType"] == "complete"


def test_protocol_errors_answered_by_the_proxy(replay):
    r = replay("protocol")
    statuses = [e["response"]["status"] for e in r.events if e["dir"] == "p2c" and "response" in e]
    assert {403, 421, 404, 415, 400, 413, 405, 202, 200} <= set(statuses)
    upstream_methods = [
        json.loads(e["request"]["body"]).get("method")
        for e in r.events
        if e["dir"] == "p2u" and "request" in e and e["request"].get("body")
    ]
    assert upstream_methods.count("initialize") == 1  # Refused attempts never left the proxy


def test_stdio_front_routes_server_messages(replay):
    r = replay("stdio_front")
    to_client = messages(r.events, "p2c")
    methods = [m.get("method") for m in to_client]
    assert methods.count("notifications/progress") == 2
    expected = {"elicitation/create", "sampling/createMessage", "notifications/message"}
    assert expected <= set(methods)
    sessions = {
        value
        for e in r.events
        if e["dir"] == "p2c" and "response" in e
        for name, value in e["response"]["headers"]
        if name.lower() == "mcp-session-id"
    }
    assert len(sessions) == 1  # Issued by the proxy on initialize
