import io
import json
import os

import pytest

from toolguard.audit import GENESIS, AuditError, AuditLog
from toolguard.model import Indicator
from toolguard.store import Store, default_home


def _observe(store, session="s", untrusted=True, ts=1.0):
    return store.add_observation(
        session=session,
        ts=ts,
        tool="WebFetch",
        kind="web",
        untrusted=untrusted,
        private=False,
        trusted=False,
        text="hello",
        indicators=(Indicator("url", "https://x.example"),),
        digest="abc",
    )


def test_observations_roundtrip_and_sessions(store):
    first = _observe(store, ts=1.0)
    _observe(store, ts=5.0, untrusted=False)
    _observe(store, session="other", ts=2.0)
    loaded = store.observations("s")
    assert [o.id for o in loaded] == [first.id, first.id + 1]
    assert loaded[0].indicators == (Indicator("url", "https://x.example"),)
    assert [o.ts for o in store.observations("s", since=3.0)] == [5.0]
    info = {s.session: s for s in store.sessions()}
    assert info["s"].observations == 2 and info["s"].untrusted == 1
    assert store.clear_session("s") == 2
    assert store.observations("s") == []


def test_file_store_is_shared_between_connections(tmp_path):
    path = tmp_path / "g.db"
    one, two = Store(path), Store(path)
    _observe(one)
    assert len(two.observations("s")) == 1
    if os.name != "nt":
        assert oct(path.stat().st_mode & 0o777) == "0o600"
    one.close()
    two.close()


def test_default_home_and_store(monkeypatch, tmp_path):
    monkeypatch.setenv("TOOLGUARD_HOME", str(tmp_path / "h"))
    assert default_home() == tmp_path / "h"
    store = Store()
    assert store.path == str(tmp_path / "h" / "guard.db")
    store.close()


def test_approval_lifecycle(store):
    pending = store.create_approval(session="s", fingerprint="f", tool="t", summary="x", now=10.0)
    assert store.get_approval(pending.id).status == "pending"
    assert [a.id for a in store.list_approvals("pending")] == [pending.id]
    assert store.decide_approval(pending.id, "approved", "alice", 11.0)
    assert not store.decide_approval(pending.id, "denied", "bob", 12.0)  # Already decided
    latest = store.latest_approval("f", "s")
    assert latest.status == "approved" and latest.decided_by == "alice"
    assert store.consume_approval(pending.id)
    assert not store.consume_approval(pending.id)  # Single use
    assert store.get_approval(pending.id).status == "consumed"
    assert store.get_approval("missing") is None
    with pytest.raises(ValueError):
        store.decide_approval(pending.id, "maybe", "x", 1.0)


def test_audit_chain_and_verification(store):
    log = AuditLog(store)
    first = log.append("decision", "s", {"tool": "Bash", "n": 1})
    second = log.append("decision", "s", {"tool": "Bash", "n": 2})
    assert first["prev"] == GENESIS and second["prev"] == first["hash"]
    report = log.verify()
    assert report.ok and report.records == 2 and report.head == second["hash"]
    out = io.StringIO()
    assert log.export_jsonl(out) == 2
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    assert lines[1]["data"]["n"] == 2 and lines[1]["hash"] == second["hash"]


TAMPER_CASES = [
    ("UPDATE audit SET body = replace(body, '\"n\":2', '\"n\":9') WHERE seq = 2", "hash mismatch"),
    ("DELETE FROM audit WHERE seq = 2", "sequence gap"),
    ("UPDATE audit SET prev = 'x' WHERE seq = 3", "broken link"),
    ("UPDATE audit SET body = 'not json' WHERE seq = 2", "unreadable record"),
    (
        "UPDATE audit SET body = replace(body, '\"seq\":2', '\"seq\":7') WHERE seq = 2",
        "sequence mismatch",
    ),
]


@pytest.mark.parametrize(("tamper", "error"), TAMPER_CASES)
def test_audit_detects_tampering(store, tamper, error):
    log = AuditLog(store)
    for n in range(1, 5):
        log.append("decision", "s", {"n": n})
    store.conn.execute(tamper)
    report = log.verify()
    assert not report.ok and report.error == error


def test_plain_chain_can_be_rewritten_but_hmac_chain_cannot(tmp_path):
    plain = Store(tmp_path / "plain.db")
    log = AuditLog(plain)
    log.append("decision", "s", {"n": 1})
    # An attacker with write access recomputes the whole (unkeyed) chain...
    body = json.dumps(
        {"data": {"n": 666}, "event": "decision", "seq": 1, "session": "s", "ts": "x"},
        separators=(",", ":"),
        sort_keys=True,
    )
    plain.conn.execute(
        "UPDATE audit SET body = ?, hash = ? WHERE seq = 1", (body, log._digest(GENESIS, body))
    )
    assert log.verify().ok  # ...which a plain hash chain cannot detect (needs an anchor)

    keyed_store = Store(tmp_path / "keyed.db")
    keyed = AuditLog(keyed_store, key=b"secret-key")
    keyed.append("decision", "s", {"n": 1})
    forged = AuditLog.__new__(AuditLog)
    forged.key = None
    keyed_store.conn.execute(
        "UPDATE audit SET body = ?, hash = ? WHERE seq = 1",
        (body, forged._digest(GENESIS, body)),
    )
    assert keyed.verify().error == "hash mismatch"
    assert keyed.verify().algorithm == "hmac-sha256"


def test_key_mismatch_errors(store):
    AuditLog(store, key=b"k")
    with pytest.raises(AuditError, match="HMAC-protected"):
        AuditLog(store)
    other = Store(":memory:")
    AuditLog(other)
    with pytest.raises(AuditError, match="without a key"):
        AuditLog(other, key=b"k")
