"""Replay MCP traffic captured from real servers behind the proxy.

The fixtures in ``fixtures/mcp_live`` were recorded with the official Python SDK
client and real servers in a throwaway container (see its README). Each replay
feeds the recorded client and server lines, in their captured order, to in-process
proxies and checks that the proxies write exactly what was recorded: the relayed
lines byte for byte, and the proxy's own messages (refusals, errors, elicitations)
up to the random elicitation ids, which are mapped.
"""

import base64
import json
import re
import time

import pytest

from conftest import FIXTURES, Inbox
from toolguard import Policy
from toolguard.adapters.mcp_proxy import McpProxy
from toolguard.approvals import ChallengeSettings, QueueApprover, answer_challenge

LIVE = FIXTURES / "mcp_live"
INDEX = json.loads((LIVE / "index.json").read_text(encoding="utf-8"))
SCENARIOS = sorted(p.stem for p in LIVE.glob("*.json") if p.stem != "index")
RANDOM_ELICITATION_ID = re.compile(rb"toolguard-[0-9a-f]{24}")
RANDOM_APPROVAL_ID = re.compile(rb"(?<=approval )[0-9a-f]{8}\b")


def load(name):
    return json.loads((LIVE / f"{name}.json").read_text(encoding="utf-8"))


def raw(event):
    if "b64" in event:
        return base64.b64decode(event["b64"])
    return event["line"].encode("utf-8")


def messages(events, direction, server=None):
    """Return the parsed JSON messages of ``events`` in one direction."""
    found = []
    for event in events:
        if event["dir"] == direction and server in (None, event["server"]):
            try:
                found.append(json.loads(raw(event).decode("utf-8", "replace")))
            except ValueError:
                found.append(None)
    return found


class Sink:
    """A byte stream that keeps each written line."""

    def __init__(self):
        self.lines = []
        self.gone = False

    def write(self, data):
        if not self.gone:  # Writes to a process that has exited are lost
            self.lines.append(bytes(data))

    def flush(self):
        pass


class FakeServer:
    """Stands in for the server process; the replay feeds its recorded output."""

    def __init__(self):
        self.stdin = Sink()


def _wait_for(condition, what, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError(f"replay stalled waiting for {what}")
        time.sleep(0.005)


class Replay:
    """Runs one captured scenario through in-process proxies."""

    def __init__(self, fixture, make_guard, store, clock, tmp_path):
        self.fixture = fixture
        self.events = fixture["events"]
        self.store, self.clock = store, clock
        # The live queue scenario used a file notifier; the others had none (fail closed).
        oob = any(e["dir"] == "oob" for e in self.events)
        self.inbox = Inbox("file")
        policy = fixture["policy"]
        if policy != "balanced":
            path = tmp_path / "policy.toml"
            path.write_text(policy, encoding="utf-8")
            policy = Policy.load(str(path))
        self.proxies = {}
        for server in fixture["servers"]:
            guard = make_guard(policy)
            notifiers = [self.inbox] if oob else []
            queue = QueueApprover(store, clock=clock, audit=guard.audit, notifiers=notifiers)
            proxy = McpProxy(guard, server, [], client_out=Sink(), queue=queue)
            proxy.client_in = None
            proxy.server = FakeServer()
            self.proxies[server] = proxy
        self.ids = {}  # Recorded random ids (elicitations, approvals) -> replayed ones
        # A server killed by a signal reads nothing after its last recorded exchange.
        killed = {e["server"] for e in self.events if e["dir"] == "server-exit" and e["code"] < 0}
        self.dies_after = {
            max(
                i
                for i, e in enumerate(self.events)
                if e.get("server") == server and e["dir"] in ("p2s", "s2p")
            ): server
            for server in killed
        }

    def out(self, server, direction):
        proxy = self.proxies[server]
        return proxy.client_out.lines if direction == "p2c" else proxy.server.stdin.lines

    def run(self):
        recorded = {(s, d): 0 for s in self.proxies for d in ("p2c", "p2s")}
        for index, event in enumerate(self.events):
            direction, server = event["dir"], event.get("server")
            if direction in ("p2c", "p2s"):
                recorded[server, direction] += 1
            elif direction == "c2p":
                self._barrier(server, "p2c", recorded[server, "p2c"])
                self.proxies[server].handle_client_line(self._map_ids(raw(event)))
            elif direction == "s2p":
                self._barrier(server, "p2s", recorded[server, "p2s"])
                self.proxies[server].handle_server_line(raw(event))
            elif direction == "oob":
                (pending,) = self.store.list_approvals("pending")
                settings = ChallengeSettings()
                result = answer_challenge(
                    self.store,
                    pending.id,
                    self.inbox.code,
                    by="cli:operator",
                    settings=settings,
                    now=self.clock(),
                )
                assert result.status == "approved"
            if index in self.dies_after:
                self._barrier(server, "p2s", recorded[server, "p2s"])
                self.proxies[self.dies_after[index]].server.stdin.gone = True
        for (server, direction), count in recorded.items():
            self._barrier(server, direction, count)

    def _barrier(self, server, direction, count):
        """Wait until the replayed proxy has written as many lines as were recorded."""
        lines = self.out(server, direction)
        _wait_for(lambda: len(lines) >= count, f"{server} {direction} line {count}")
        if direction == "p2c":
            self._learn_ids(server)

    def _learn_ids(self, server):
        recorded = [raw(e) for e in self.events if e["dir"] == "p2c" and e["server"] == server]
        replayed = self.out(server, "p2c")
        for pattern in (RANDOM_ELICITATION_ID, RANDOM_APPROVAL_ID):
            old = list(dict.fromkeys(m for line in recorded for m in pattern.findall(line)))
            new = list(dict.fromkeys(m for line in replayed for m in pattern.findall(line)))
            self.ids.update(zip(old, new, strict=False))

    def _map_ids(self, line):
        for old, new in self.ids.items():
            line = line.replace(old, new)
        return line

    def normalized(self, server):
        """Return the recorded and replayed client-side output, with mapped ids."""
        recorded = [raw(e) for e in self.events if e["dir"] == "p2c" and e["server"] == server]
        return [self._map_ids(line) for line in recorded], self.out(server, "p2c")


@pytest.fixture
def replay(make_guard, store, clock, tmp_path):
    def _run(name):
        r = Replay(load(name), make_guard, store, clock, tmp_path)
        r.run()
        return r

    return _run


def test_fixtures_are_sanitized_and_versioned():
    versions = INDEX["versions"]
    assert versions["mcp (client)"] == "2.3.0"
    assert versions["@modelcontextprotocol/server-everything"] == "1.0.0"
    assert versions["mcp-server-fetch (fetch)"] == "2026.10.10"
    assert "hostname" not in versions
    assert set(SCENARIOS) == set(INDEX["scenarios"]) - {"large"}
    for name in SCENARIOS:
        text = (LIVE / f"{name}.json").read_text(encoding="utf-8")
        assert "C:\\\\Users" not in text and "/Users/" not in text


@pytest.mark.parametrize("name", SCENARIOS)
def test_replay_matches_the_recorded_traffic(replay, name):
    r = replay(name)
    for server, proxy in r.proxies.items():
        recorded = [raw(e) for e in r.events if e["dir"] == "p2s" and e["server"] == server]
        assert proxy.server.stdin.lines == recorded, f"{server}: lines sent to the server"
        expected, replayed = r.normalized(server)
        assert replayed == expected, f"{server}: lines sent to the client"


def test_handshake_and_capabilities_pass_through(replay):
    r = replay("handshake")
    events = r.events
    sent = messages(events, "c2p")
    assert sent[0]["method"] == "server/discover"  # SDK v2 probes the 2026-07-28 era first
    discover = messages(events, "s2p")[0]
    assert discover["error"]["code"] == -32601  # The server predates it: initialize follows
    init = next(m for m in sent if m.get("method") == "initialize")
    assert init["params"]["protocolVersion"] == "2025-11-25"
    assert init["params"]["capabilities"]["elicitation"] == {"form": {}, "url": {}}
    assert init in messages(events, "p2s")  # Forwarded unchanged
    reply = next(m for m in messages(events, "s2p") if m.get("id") == init["id"])
    assert reply["result"]["protocolVersion"] == "2025-11-25"
    assert "tasks" in reply["result"]["capabilities"]
    assert r.proxies["everything"].client_elicitation is True
    methods = {m.get("method") for m in sent}
    assert {"tools/list", "prompts/get", "resources/read", "completion/complete"} <= methods
    assert {"resources/subscribe", "logging/setLevel"} <= methods


def test_notifications_and_server_requests_pass_through(replay):
    r = replay("tools")
    to_client = messages(r.events, "p2c")
    methods = [m.get("method") for m in to_client if isinstance(m, dict)]
    assert methods.count("notifications/progress") >= 2
    assert "notifications/message" in methods
    for request in ("elicitation/create", "sampling/createMessage", "roots/list"):
        asked = next(m for m in to_client if m.get("method") == request)
        assert isinstance(asked["id"], int)  # The server's own request, not the proxy's
        answer = next(m for m in messages(r.events, "c2p") if m.get("id") == asked["id"])
        assert answer in messages(r.events, "p2s")
    blocks = [
        block
        for m in to_client
        if isinstance(m, dict) and isinstance(m.get("result"), dict)
        for block in m["result"].get("content") or []
    ]
    assert {"image", "resource_link", "resource"} <= {b["type"] for b in blocks}
    assert any(b["type"] == "image" and b["mimeType"] == "image/png" for b in blocks)
    assert r.proxies["everything"].guard.store.observations("s1") == []


def test_real_output_taints_the_session_across_servers(replay):
    r = replay("provenance")
    decisions = {
        (d["tool"], json.dumps(d["args"], sort_keys=True)): d["effective"]
        for d in (rec["data"] for rec in r.proxies["fetch"].guard.audit.records())
        if "effective" in d
    }
    archive = json.dumps({"entityNames": ["Archive-2019"]})
    draft = json.dumps({"entityNames": ["Draft-Plan"]})
    assert decisions["mcp__memory__delete_entities", draft] == "allow"  # Before the page
    assert decisions["mcp__memory__delete_entities", archive] == "block"
    observed = [o.tool for o in r.store.observations("s1")]
    assert observed == [
        "mcp__fetch__fetch",
        "mcp__fetch__fetch",
        "mcp__filesystem__read_text_file",
    ]
    deletes = [
        m["params"]["arguments"]
        for m in messages(r.events, "p2s", "memory")
        if m.get("method") == "tools/call" and m["params"]["name"] == "delete_entities"
    ]
    assert deletes == [{"entityNames": ["Draft-Plan"]}]  # The blocked one never left
    refused = [m for m in messages(r.events, "p2c") if m.get("result", {}).get("isError") is True]
    assert [text["text"].splitlines()[0] for m in refused for text in m["result"]["content"]] == [
        "toolguard: BLOCK mcp__memory__delete_entities (sink: destructive)",
        "toolguard: CONFIRM mcp__fetch__fetch (sink: web)",
        "toolguard: CONFIRM mcp__filesystem__write_file (sink: autoexec)",
    ]


def test_confirmation_through_elicitation(replay):
    r = replay("elicitation")
    asked = [
        m for m in messages(r.events, "p2c", "memory") if m.get("method") == "elicitation/create"
    ]
    assert len(asked) == 3
    assert asked[0]["params"]["requestedSchema"]["required"] == ["approve"]
    answers = [
        m["result"]
        for m in messages(r.events, "c2p", "memory")
        if str(m.get("id", "")).startswith("toolguard-")
    ]
    assert [a["action"] for a in answers] == ["accept", "decline", "cancel"]
    deletes = [
        m["params"]["arguments"]["entityNames"]
        for m in messages(r.events, "p2s", "memory")
        if m.get("method") == "tools/call" and m["params"]["name"] == "delete_entities"
    ]
    assert deletes == [["Old-Minutes"]]
    statuses = [
        (d["data"]["approval"] or {}).get("status")
        for d in r.proxies["memory"].guard.audit.records()
        if d["event"] == "decision" and d["data"]["category"] == "destructive"
    ]
    assert statuses == ["approved", "denied", "denied"]


def test_confirmation_through_the_out_of_band_queue(replay):
    r = replay("queue")
    assert len(r.inbox.notices) == 1
    for line in r.proxies["memory"].client_out.lines:
        assert r.inbox.code.encode() not in line  # The code never reaches the model
    deletes = [
        m
        for m in messages(r.events, "p2s", "memory")
        if m.get("method") == "tools/call" and m["params"]["name"] == "delete_entities"
    ]
    assert len(deletes) == 1  # Only the retry after the human approved


def test_task_result_taints_the_session(replay):
    r = replay("tasks")
    sent = messages(r.events, "c2p", "everything")
    call = next(m for m in sent if m.get("method") == "tools/call")
    assert "task" in call["params"]
    (observation,) = r.store.observations("s1")
    assert observation.tool == "mcp__everything__simulate-research-query"
    assert "archive-2019" in observation.text  # Normalized text


def test_malformed_input_is_answered_by_the_proxy(replay):
    r = replay("protocol")
    sent = [e for e in r.events if e["dir"] == "c2p"]
    assert any("b64" in e for e in sent)  # A line that is not valid UTF-8
    forwarded = messages(r.events, "p2s")
    echoes = [m["params"]["arguments"]["message"] for m in forwarded if m.get("id") == 41]
    assert echoes == ["caf\ufffd"]
    assert "this is not json" not in json.dumps(
        [e.get("line") for e in r.events if e["dir"] == "p2s"]
    )
    batch = [m for m in forwarded if m.get("id") in (42, 43)]
    assert [m["params"]["arguments"]["message"] for m in batch] == ["first", "second"]
    ids = [m["id"] for m in messages(r.events, "p2c") if isinstance(m, dict) and "id" in m]
    assert sorted(map(str, ids)) == sorted(map(str, set(ids)))  # One answer per request


def test_stateless_revision_is_guarded_and_confirmations_fail_closed(replay):
    # Protocol 2026-07-28: no initialize, so the proxy never learns that the client
    # supports elicitation; confirmations go to the queue, which has no notifier here.
    r = replay("modern")
    sent = messages(r.events, "c2p")
    assert sent[0]["method"] == "server/discover"
    assert all(m.get("method") != "initialize" for m in sent)
    meta = next(m for m in sent if m.get("method") == "tools/call")["params"]["_meta"]
    assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
    assert "elicitation" in meta["io.modelcontextprotocol/clientCapabilities"]
    assert r.proxies["mail"].client_elicitation is False
    refusals = [m["result"] for m in messages(r.events, "p2c") if m["result"].get("isError")]
    assert [x["content"][0]["text"].splitlines()[0] for x in refusals] == [
        "toolguard: BLOCK mcp__mail__send_email (sink: send)",
        "toolguard: CONFIRM mcp__mail__send_email (sink: send)",
    ]
    assert all(x["resultType"] == "complete" for x in refusals)
    calls = [
        m["params"]["name"] for m in messages(r.events, "p2s") if m.get("method") == "tools/call"
    ]
    assert calls == ["read_inbox"]


def test_crash_and_disconnect_exit_codes():
    crash = load("crash")["events"]
    exits = {e["dir"]: e["code"] for e in crash if e["dir"].endswith("exit")}
    assert exits == {"server-exit": -9, "client-exit": 137}
    protocol = INDEX["scenarios"]["protocol"]["observed"]
    assert protocol["exit_code"] == 143 and protocol["exit_seconds"] < 10
    assert INDEX["scenarios"]["large"]["observed"]["png_bytes"] > 500_000
