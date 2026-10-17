import contextlib
import io
import json

import pytest

from toolguard.approvals import (
    ApprovalConfig,
    ApprovalOutcome,
    ApprovalRequest,
    CallbackApprover,
    ChainApprover,
    ChallengeSettings,
    ConsoleApprover,
    DenyApprover,
    QueueApprover,
    answer_challenge,
    apply_outcome,
)
from toolguard.audit import AuditLog
from toolguard.model import Action, Decision
from toolguard.notifiers import CallbackNotifier, ConfigError, NotifyError
from toolguard.store import Store

REQ = ApprovalRequest(session="s", tool="Bash", fingerprint="fp", summary="why", args_preview={})


def test_deny_and_callback():
    assert DenyApprover().request(REQ).status == "denied"
    seen = []
    approver = CallbackApprover(lambda r: seen.append(r) or True, name="ui")
    outcome = approver.request(REQ)
    assert outcome == ApprovalOutcome("approved", by="ui")
    assert seen == [REQ]


def _console(answer):
    writer = io.StringIO()

    @contextlib.contextmanager
    def opener():
        yield io.StringIO(answer), writer

    return opener, writer


def test_console_approver_reads_the_terminal():
    opener, writer = _console("y\n")
    assert ConsoleApprover(opener).request(REQ).status == "approved"
    assert "Allow this tool call?" in writer.getvalue() and "why" in writer.getvalue()
    opener, _ = _console("\n")
    assert ConsoleApprover(opener).request(REQ).status == "denied"


def test_console_unavailable_fails_closed():
    @contextlib.contextmanager
    def no_console():
        yield None

    outcome = ConsoleApprover(no_console).request(REQ)
    assert outcome.status == "denied" and "no interactive terminal" in outcome.note


def _approve(store, approval_id, code, clock, key=None):
    settings = ChallengeSettings(key=key)
    return answer_challenge(store, approval_id, code, by="alice", settings=settings, now=clock())


def _events(store):
    return [r["data"] for r in AuditLog(store).records() if r["event"] == "approval"]


def test_queue_approver_lifecycle(store, clock, inbox):
    queue = QueueApprover(store, ttl=60, clock=clock, notifiers=[inbox])
    first = queue.request(REQ)
    assert first.status == "pending" and first.approval_id and first.channel == "inbox"
    (notice,) = inbox.notices
    assert notice.approval_id == first.approval_id and notice.summary == "why"
    assert queue.request(REQ).approval_id == first.approval_id  # No duplicate requests
    assert len(inbox.notices) == 1  # ... and no second notification
    assert _approve(store, first.approval_id, inbox.code, clock).status == "approved"
    approved = queue.request(REQ)
    assert approved.status == "approved" and approved.by == "alice"
    again = queue.request(REQ)  # Single use: a new request with a new code is created
    assert again.status == "pending" and again.approval_id != first.approval_id
    assert inbox.notices[-1].code != notice.code
    events = _events(store)
    assert [e["status"] for e in events] == ["created", "notified", "created", "notified"]
    assert events[1]["channel"] == "inbox"
    for code in (notice.code, inbox.code):
        assert code not in json.dumps(events)


def test_queue_approver_denial_and_expiry(store, clock, inbox):
    queue = QueueApprover(store, ttl=60, clock=clock, notifiers=[inbox])
    pending = queue.request(REQ)
    store.decide_approval(pending.approval_id, "denied", "bob", clock())
    assert queue.request(REQ).status == "denied"
    clock.advance(120)
    assert queue.request(REQ).status == "pending"  # Stale denial: ask again
    newer = store.latest_approval("fp", "s")
    assert _approve(store, newer.id, inbox.code, clock).status == "approved"
    clock.advance(120)
    assert queue.request(REQ).status == "pending"  # Approval expired unused


def test_code_expiry_creates_a_new_challenge(store, clock, inbox):
    settings = ChallengeSettings(code_ttl=30)
    queue = QueueApprover(store, clock=clock, notifiers=[inbox], settings=settings)
    first = queue.request(REQ)
    old_code = inbox.code
    clock.advance(31)
    second = queue.request(REQ)
    assert second.status == "pending" and second.approval_id != first.approval_id
    assert store.get_approval(first.approval_id).status == "expired"
    assert _approve(store, first.approval_id, old_code, clock).status == "not_pending"
    assert "expired" in [e["status"] for e in _events(store)]


def test_lockout_denies_until_stale(store, clock, inbox):
    settings = ChallengeSettings(max_attempts=2)
    queue = QueueApprover(store, ttl=60, clock=clock, notifiers=[inbox], settings=settings)
    pending = queue.request(REQ)
    for _ in range(2):
        answer_challenge(
            store, pending.approval_id, "WRONG", by="agent", settings=settings, now=clock()
        )
    locked = queue.request(REQ)
    assert locked.status == "denied" and "too many wrong codes" in locked.note
    clock.advance(61)
    assert queue.request(REQ).status == "pending"


def test_notifier_fallback_and_fail_closed(store, clock, inbox):
    def broken(notice):
        raise NotifyError("gateway down")

    telegram = CallbackNotifier(broken, "telegram")
    queue = QueueApprover(store, clock=clock, notifiers=[telegram, inbox])
    outcome = queue.request(REQ)
    assert outcome.status == "pending" and outcome.channel == "inbox"
    failed = _events(store)[1]
    assert failed["status"] == "notify_failed" and failed["error"] == "gateway down"
    assert failed["channel"] == "telegram"
    assert store.get_approval(outcome.approval_id).channel == "inbox"

    other = ApprovalRequest(
        session="s", tool="Bash", fingerprint="f2", summary="", args_preview={}
    )
    dead = QueueApprover(store, clock=clock, notifiers=[telegram])
    refused = dead.request(other)
    assert refused.status == "denied" and "could not be delivered" in refused.note
    assert store.get_approval(refused.approval_id).status == "undeliverable"
    last = _events(store)[-1]
    assert last["status"] == "undeliverable" and last["channels"] == ["telegram"]
    # Retrying unlocks nothing: delivery is attempted again and fails closed again.
    assert dead.request(other).status == "denied"


def test_forged_decisions_are_rejected_with_a_key(store, clock, inbox):
    settings = ChallengeSettings(key=b"approval-key")
    queue = QueueApprover(store, clock=clock, notifiers=[inbox], settings=settings)
    pending = queue.request(REQ)
    # Someone with write access to the database, but without the key, flips the row.
    store.decide_approval(pending.approval_id, "approved", "cli:mallory", clock())
    forged = queue.request(REQ)
    assert forged.status == "denied" and "integrity check" in forged.note
    assert _events(store)[-1]["status"] == "rejected"
    fresh = queue.request(REQ)
    assert fresh.status == "pending"
    result = _approve(store, fresh.approval_id, inbox.code, clock, key=b"approval-key")
    assert result.status == "approved"
    assert queue.request(REQ).status == "approved"


def test_codeless_pending_approvals_are_replaced(store, clock, inbox):
    legacy = store.create_approval(
        session="s", fingerprint="fp", tool="Bash", summary="old", now=clock()
    )
    outcome = QueueApprover(store, clock=clock, notifiers=[inbox]).request(REQ)
    assert outcome.status == "pending" and outcome.approval_id != legacy.id
    assert store.get_approval(legacy.id).status == "expired"


def test_default_audit_log_uses_the_environment_key(store, clock, inbox):
    queue = QueueApprover(store, clock=clock, notifiers=[inbox])
    queue.request(REQ)
    assert queue.audit.algorithm == "sha256"


def test_apply_outcome():
    decision = Decision("Bash", {}, Action.CONFIRM)
    apply_outcome(decision, ApprovalOutcome("pending", approval_id="a1", channel="telegram"))
    assert decision.effective == Action.BLOCK and decision.approval_channel == "telegram"
    assert "via telegram" in decision.explain()
    apply_outcome(decision, ApprovalOutcome("denied", note="nobody"))
    assert decision.reasons[-1].message == "nobody"
    apply_outcome(decision, ApprovalOutcome("approved", by="alice", note="ignored"))
    assert decision.allowed and decision.reasons[-1].message == "nobody"


def test_chain_approver_falls_through_to_definitive_answer(store, clock, inbox):
    @contextlib.contextmanager
    def no_console():
        yield None

    queue = QueueApprover(store, clock=clock, notifiers=[inbox])
    chain = ChainApprover(ConsoleApprover(no_console), queue)
    assert chain.request(REQ).status == "pending"
    human_no = ChainApprover(CallbackApprover(lambda r: False, "ui"), QueueApprover(store))
    assert human_no.request(REQ).status == "denied"
    assert ChainApprover().request(REQ).status == "denied"


CONFIG = """
[challenge]
code_ttl = 120
max_attempts = 3
length = 16
key_env = "MY_KEY"

[[notifier]]
type = "file"
path = "/var/lib/toolguard-ops/approvals.log"

[[notifier]]
type = "telegram"
chat_id = "42"
"""


def test_config_from_file(tmp_path, monkeypatch):
    path = tmp_path / "approvals.toml"
    path.write_text(CONFIG, encoding="utf-8")
    monkeypatch.setenv("MY_KEY", "k")
    config = ApprovalConfig.load(path)
    assert config.settings == ChallengeSettings(120.0, 3, 16, b"k")
    assert [n.name for n in config.notifiers] == ["file", "telegram"]
    assert config.path == str(path)
    with Store(tmp_path / "g.db") as store:
        queue = QueueApprover.from_config(store, config)
        assert queue.settings.length == 16 and len(queue.notifiers) == 2
    monkeypatch.setenv("TOOLGUARD_APPROVALS_CONFIG", str(path))
    assert ApprovalConfig.load().path == str(path)


def test_config_defaults_and_errors(tmp_path):
    default = ApprovalConfig.load()  # Nothing in TOOLGUARD_HOME: no notifier, fail closed
    assert default.notifiers == () and default.path is None
    home = tmp_path / "toolguard-home"
    home.mkdir(exist_ok=True)
    (home / "approvals.toml").write_text('[[notifier]]\ntype = "desktop"\n', encoding="utf-8")
    assert [n.name for n in ApprovalConfig.load().notifiers] == ["desktop"]
    with pytest.raises(ConfigError, match="not found"):
        ApprovalConfig.load(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("not toml [", encoding="utf-8")
    with pytest.raises(ConfigError, match=r"bad.toml"):
        ApprovalConfig.load(bad)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"surprise": 1}, "unknown key"),
        ({"challenge": {"pepper": 1}}, "accepts only"),
        ({"challenge": []}, "accepts only"),
        ({"challenge": {"key_env": ""}}, "key_env"),
        ({"challenge": {"length": 4}}, "between 10 and 32"),
        ({"challenge": {"code_ttl": "soon"}}, "challenge"),
        ({"notifier": {"type": "desktop"}}, "notifier"),
        ({"notifier": [{"type": "desktop"}, {"type": "desktop"}]}, "unique"),
        ({"notifier": [{"type": "telegram", "chat_id": 1, "token": "x"}]}, "environment"),
    ],
)
def test_config_rejects_bad_tables(data, message):
    with pytest.raises(ConfigError, match=message):
        ApprovalConfig.from_dict(data)
