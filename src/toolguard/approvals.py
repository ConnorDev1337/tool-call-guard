"""Human approval channels for decisions that require confirmation.

Approvals must come from a channel the agent cannot drive: a tool the model can
call, or text it can write, is never an approval. Hence the console channel uses
the controlling terminal rather than stdin/stdout, which may belong to the agent,
and queued requests are decided with ``toolguard approve`` in an interactive
terminal.
"""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Protocol, TextIO

from .store import Store

APPROVAL_TTL = 600.0  # Seconds an approval stays usable after a human decides


@dataclass(frozen=True)
class ApprovalRequest:
    """A tool call submitted for human approval."""

    session: str
    tool: str
    fingerprint: str
    summary: str  # Decision.explain(): rules and evidence, no raw secrets
    args_preview: Any  # Redacted arguments


@dataclass(frozen=True)
class ApprovalOutcome:
    """Answer of an approval channel; ``by`` identifies who decided, if anyone."""

    status: str  # "approved" | "denied" | "pending"
    by: str | None = None
    approval_id: str | None = None
    note: str | None = None


class Approver(Protocol):
    """Interface of an approval channel."""

    def request(self, req: ApprovalRequest) -> ApprovalOutcome: ...


class DenyApprover:
    """Fail-closed default: deny every request because nobody can be asked."""

    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        return ApprovalOutcome("denied", note="no human approval channel is configured")


class CallbackApprover:
    """Delegate the decision to a callback, e.g. the embedding application's UI."""

    def __init__(
        self, callback: Callable[[ApprovalRequest], bool], name: str = "callback"
    ) -> None:
        self.callback = callback
        self.name = name

    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        approved = bool(self.callback(req))
        return ApprovalOutcome("approved" if approved else "denied", by=self.name)


@contextlib.contextmanager
def open_console() -> Iterator[tuple[TextIO, TextIO] | None]:
    """Yield ``(reader, writer)`` for the controlling terminal, or ``None`` if unavailable."""
    handles: list[TextIO] = []
    try:
        if os.name == "nt":
            reader = open("CONIN$", encoding="utf-8")  # noqa: SIM115
            handles.append(reader)
            writer = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115
            handles.append(writer)
        else:
            tty = open("/dev/tty", "r+", encoding="utf-8")  # noqa: SIM115
            handles.append(tty)
            reader = writer = tty
    except OSError:
        yield None
    else:
        yield reader, writer
    finally:
        for handle in handles:
            with contextlib.suppress(OSError):
                handle.close()


class ConsoleApprover:
    """Ask on the controlling terminal; deny if there is none."""

    def __init__(self, opener: Callable[[], Any] = open_console) -> None:
        self.opener = opener

    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        with self.opener() as console:
            if console is None:
                return ApprovalOutcome("denied", note="no interactive terminal available")
            reader, writer = console
            writer.write("\n" + "=" * 72 + "\n" + req.summary + "\n")
            writer.write(f"Arguments (redacted): {req.args_preview}\n")
            writer.write("Allow this tool call? [y/N] ")
            writer.flush()
            answer = reader.readline().strip().lower()
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "console"
        if answer in {"y", "yes"}:
            return ApprovalOutcome("approved", by=f"console:{user}")
        return ApprovalOutcome("denied", by=f"console:{user}")


class QueueApprover:
    """Queue requests in the store for ``toolguard approve`` or ``toolguard deny``.

    The agent retries the identical call to use an approval, which is bound to the
    call fingerprint, single use and valid for ``ttl`` seconds after the decision.
    """

    def __init__(
        self, store: Store, ttl: float = APPROVAL_TTL, clock: Callable[[], float] = time.time
    ):
        self.store = store
        self.ttl = ttl
        self.clock = clock

    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        now = self.clock()
        latest = self.store.latest_approval(req.fingerprint, req.session)
        fresh = (
            latest is not None and latest.decided is not None and now - latest.decided <= self.ttl
        )
        approved = latest is not None and latest.status == "approved" and fresh
        if approved and self.store.consume_approval(latest.id):
            return ApprovalOutcome("approved", by=latest.decided_by, approval_id=latest.id)
        if latest is not None and latest.status == "denied" and fresh:
            return ApprovalOutcome("denied", by=latest.decided_by, approval_id=latest.id)
        if latest is not None and latest.status == "pending":
            return ApprovalOutcome("pending", approval_id=latest.id)
        created = self.store.create_approval(
            session=req.session,
            fingerprint=req.fingerprint,
            tool=req.tool,
            summary=req.summary,
            now=now,
        )
        return ApprovalOutcome("pending", approval_id=created.id)


class ChainApprover:
    """Try approvers in order; unattributed denials (no channel available) fall through."""

    def __init__(self, *approvers: Approver) -> None:
        self.approvers = approvers

    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        outcome = ApprovalOutcome("denied", note="no approver configured")
        for approver in self.approvers:
            outcome = approver.request(req)
            if outcome.status in {"approved", "pending"} or outcome.by:
                return outcome
        return outcome
