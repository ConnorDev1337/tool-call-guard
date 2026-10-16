"""Human approval channels for decisions that require confirmation.

The approval channel is the crux of the design from an AI-control point of
view: it must be *out of band*, i.e. something the agent cannot drive. A tool
the model can call, or text the model can write, is never an approval.
Channels provided here:

* :class:`ConsoleApprover` asks on the controlling terminal (``/dev/tty`` or
  ``CONIN$``/``CONOUT$``), not on stdin/stdout, which may belong to the agent.
* :class:`QueueApprover` records a pending request; a human approves it with
  ``toolguard approve <id>`` from an interactive terminal and the agent retries
  the *identical* call, which consumes the approval (single use, short TTL).
* :class:`CallbackApprover` lets an embedding application plug its own UI.
* :class:`DenyApprover` is the fail-closed default when nobody can be asked.
"""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Protocol, TextIO

from .store import Store

APPROVAL_TTL = 600.0  # seconds an approval stays usable after a human decides


@dataclass(frozen=True)
class ApprovalRequest:
    session: str
    tool: str
    fingerprint: str
    summary: str  # Decision.explain(): rules, evidence, no raw secrets
    args_preview: Any  # redacted arguments


@dataclass(frozen=True)
class ApprovalOutcome:
    status: str  # "approved" | "denied" | "pending"
    by: str | None = None
    approval_id: str | None = None
    note: str | None = None


class Approver(Protocol):
    def request(self, req: ApprovalRequest) -> ApprovalOutcome: ...


class DenyApprover:
    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        return ApprovalOutcome("denied", note="no human approval channel is configured")


class CallbackApprover:
    def __init__(self, callback: Callable[[ApprovalRequest], bool], name: str = "callback") -> None:
        self.callback = callback
        self.name = name

    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        approved = bool(self.callback(req))
        return ApprovalOutcome("approved" if approved else "denied", by=self.name)


@contextlib.contextmanager
def open_console() -> Iterator[tuple[TextIO, TextIO] | None]:
    """The process' controlling terminal, independent of stdin/stdout."""
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
    """Try approvers in order until one gives a definitive answer."""

    def __init__(self, *approvers: Approver) -> None:
        self.approvers = approvers

    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        outcome = ApprovalOutcome("denied", note="no approver configured")
        for approver in self.approvers:
            outcome = approver.request(req)
            if outcome.status in {"approved", "pending"} or outcome.by:
                return outcome
        return outcome
