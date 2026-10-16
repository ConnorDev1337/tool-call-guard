import json
import os
import queue
import sys
import threading

import pytest

from conftest import FIXTURES
from toolguard.adapters.mcp_proxy import McpProxy

SERVER = [sys.executable, str(FIXTURES / "fake_mail_server.py")]


class Harness:
    """Runs McpProxy in-process, wired to the fake server and a fake client."""

    def __init__(self, guard, elicitation_timeout=10.0):
        c2p_r, c2p_w = os.pipe()
        p2c_r, p2c_w = os.pipe()
        self.to_proxy = os.fdopen(c2p_w, "wb", buffering=0)
        self.from_proxy = os.fdopen(p2c_r, "rb")
        self.proxy = McpProxy(
            guard,
            "mail",
            SERVER,
            client_in=os.fdopen(c2p_r, "rb"),
            client_out=os.fdopen(p2c_w, "wb"),
            elicitation_timeout=elicitation_timeout,
        )
        self.lines: queue.Queue = queue.Queue()
        self.exit_code: list[int] = []
        threading.Thread(
            target=lambda: self.exit_code.append(self.proxy.run()), daemon=True
        ).start()
        threading.Thread(target=self._read, daemon=True).start()
        self.next_id = 0

    def _read(self):
        for line in self.from_proxy:
            try:
                self.lines.put(json.loads(line))
            except ValueError:
                self.lines.put(line)

    def send(self, message):
        self.to_proxy.write((json.dumps(message) + "\n").encode())

    def recv(self, timeout=15):
        return self.lines.get(timeout=timeout)

    def request(self, method, params=None):
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}})
        return self.next_id

    def call(self, name, arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def initialize(self, elicitation=False):
        capabilities = {"elicitation": {}} if elicitation else {}
        self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": capabilities,
                "clientInfo": {"name": "test", "version": "0"},
            },
        )
        return self.recv()

    def close(self):
        self.to_proxy.close()
        for _ in range(100):
            if self.exit_code:
                break
            threading.Event().wait(0.1)


@pytest.fixture
def harness(make_guard):
    created = []

    def _make(**kwargs):
        h = Harness(make_guard(), **kwargs)
        created.append(h)
        return h

    yield _make
    for h in created:
        h.close()


def text_of(response):
    return response["result"]["content"][0]["text"]


def test_passthrough_and_observation(harness):
    h = harness()
    assert h.initialize()["result"]["serverInfo"]["name"] == "fake-mail"
    h.call("read_inbox", {})
    assert "evil-payments" in text_of(h.recv())
    observations = h.proxy.guard.store.observations("s1")
    assert [o.tool for o in observations] == ["mcp__mail__read_inbox"]
    h.request("ping")
    assert h.recv()["result"] == {}


def test_injected_recipient_is_refused_without_reaching_the_server(harness):
    h = harness()
    h.initialize()
    h.call("read_inbox", {})
    h.recv()
    call_id = h.call("send_email", {"to": "billing@evil-payments.example", "body": "invoices"})
    response = h.recv()
    assert response["id"] == call_id and response["result"]["isError"] is True
    assert "BLOCK mcp__mail__send_email" in text_of(response)
    decision = list(h.proxy.guard.audit.records())[-1]["data"]
    assert decision["integration"] == "mcp-proxy" and decision["effective"] == "block"


def test_confirmation_via_out_of_band_queue(harness, store, clock):
    h = harness()
    h.initialize()
    h.call("read_inbox", {})
    h.recv()
    h.call("send_email", {"to": "alice@corp.example", "body": "hi"})
    refused = h.recv()
    assert refused["result"]["isError"] and "toolguard approve" in text_of(refused)
    (pending,) = store.list_approvals("pending")
    store.decide_approval(pending.id, "approved", "cli:alice", clock())
    h.call("send_email", {"to": "alice@corp.example", "body": "hi"})
    assert text_of(h.recv()) == "sent to alice@corp.example"


@pytest.mark.parametrize(("answer", "allowed"), [(True, True), (False, False), (None, False)])
def test_confirmation_via_elicitation(harness, answer, allowed):
    h = harness(elicitation_timeout=1.0 if answer is None else 10.0)
    h.initialize(elicitation=True)
    h.call("read_inbox", {})
    h.recv()
    h.call("send_email", {"to": "alice@corp.example", "body": "hi"})
    elicitation = h.recv()
    assert elicitation["method"] == "elicitation/create"
    assert "tainted" in elicitation["params"]["message"]
    if answer is not None:
        result = {"action": "accept", "content": {"approve": answer}}
        h.send({"jsonrpc": "2.0", "id": elicitation["id"], "result": result})
    response = h.recv()
    if allowed:
        assert text_of(response) == "sent to alice@corp.example"
    else:
        assert response["result"]["isError"] is True


def test_blank_and_non_json_lines(harness):
    h = harness()
    h.to_proxy.write(b"\n")  # Ignored
    assert h.initialize()["result"]["serverInfo"]["name"] == "fake-mail"
    h.proxy.handle_server_line(b"server log line")
    assert h.recv() == b"server log line\n"


def test_server_requests_and_notifications_pass_through(harness):
    h = harness()
    h.initialize()
    h.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    h.proxy.handle_server_line(b'{"jsonrpc":"2.0","id":"s1","method":"roots/list"}')
    assert h.recv()["method"] == "roots/list"
    h.request("ping")
    assert h.recv()["result"] == {}
