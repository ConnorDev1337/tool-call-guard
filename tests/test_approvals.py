import contextlib
import io

from toolguard.approvals import (
    ApprovalOutcome,
    ApprovalRequest,
    CallbackApprover,
    ChainApprover,
    ConsoleApprover,
    DenyApprover,
    QueueApprover,
)

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


def test_queue_approver_lifecycle(store, clock):
    queue = QueueApprover(store, ttl=60, clock=clock)
    first = queue.request(REQ)
    assert first.status == "pending" and first.approval_id
    assert queue.request(REQ).approval_id == first.approval_id  # No duplicate requests
    store.decide_approval(first.approval_id, "approved", "alice", clock())
    approved = queue.request(REQ)
    assert approved.status == "approved" and approved.by == "alice"
    again = queue.request(REQ)  # Single use: a new request is created
    assert again.status == "pending" and again.approval_id != first.approval_id


def test_queue_approver_denial_and_expiry(store, clock):
    queue = QueueApprover(store, ttl=60, clock=clock)
    pending = queue.request(REQ)
    store.decide_approval(pending.approval_id, "denied", "bob", clock())
    assert queue.request(REQ).status == "denied"
    clock.advance(120)
    assert queue.request(REQ).status == "pending"  # Stale denial: ask again
    newer = store.latest_approval("fp", "s")
    store.decide_approval(newer.id, "approved", "alice", clock())
    clock.advance(120)
    assert queue.request(REQ).status == "pending"  # Approval expired unused


def test_chain_approver_falls_through_to_definitive_answer(store, clock):
    @contextlib.contextmanager
    def no_console():
        yield None

    chain = ChainApprover(ConsoleApprover(no_console), QueueApprover(store, clock=clock))
    assert chain.request(REQ).status == "pending"
    human_no = ChainApprover(CallbackApprover(lambda r: False, "ui"), QueueApprover(store))
    assert human_no.request(REQ).status == "denied"
    assert ChainApprover().request(REQ).status == "denied"
