"""Human approval channels for decisions that require confirmation.

Approvals must come from a channel the agent cannot drive: a tool the model can
call, or text it can write, is never an approval. Hence the console channel uses
the controlling terminal rather than stdin/stdout, which may belong to the agent,
and queued requests are decided with ``toolguard approve`` in an interactive
terminal.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import secrets
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Protocol, TextIO

from .model import canonical_json
from .store import Approval, Store

APPROVAL_TTL = 600.0  # Seconds an approval stays usable after a human decides
ENV_APPROVAL_KEY = "TOOLGUARD_APPROVAL_KEY"

# Crockford base32: no I, L, O or U, so codes survive being read aloud or retyped.
CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CODE_ALIASES = str.maketrans({"I": "1", "L": "1", "O": "0"})
_UNKEYED = b"toolguard-approval-code"


# --------------------------------------------------------------------------- one-time codes


@dataclass(frozen=True)
class ChallengeSettings:
    """Parameters of the one-time code that out-of-band approvals require.

    The default 12 characters carry 60 bits from the CSPRNG: guessing online is
    capped by ``max_attempts``, and the short ``code_ttl`` leaves no time for an
    offline search of a leaked (salted) hash. ``key`` turns the stored hash and the
    decision record into HMACs that cannot be forged without it.
    """

    code_ttl: float = 300.0
    max_attempts: int = 5
    length: int = 12
    key: bytes | None = None

    def __post_init__(self) -> None:
        if not 10 <= self.length <= 32:
            raise ValueError("code length must be between 10 and 32 characters")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.code_ttl <= 0:
            raise ValueError("code_ttl must be positive")

    @property
    def algorithm(self) -> str:
        return "hmac-sha256" if self.key else "sha256"


def new_code(length: int = 12) -> str:
    """Return a random one-time code, grouped by four characters (``XXXX-XXXX-XXXX``)."""
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))
    return "-".join(raw[i : i + 4] for i in range(0, length, 4))


def normalize_code(code: str) -> str:
    """Canonicalize typed input: ignore case, spaces and dashes; read I/L as 1 and O as 0."""
    return "".join(ch for ch in code.upper() if ch not in " -\t").translate(_CODE_ALIASES)


def hash_code(code: str, *, approval_id: str, salt: str, key: bytes | None) -> str:
    """Return the stored digest of ``code``, bound to one approval and a random salt."""
    message = f"{approval_id}\n{salt}\n{normalize_code(code)}".encode()
    return hmac.new(key or _UNKEYED, message, hashlib.sha256).hexdigest()


def code_matches(approval: Approval, code: str, key: bytes | None) -> bool | None:
    """Compare ``code`` with the approval's stored digest in constant time.

    Returns ``None`` if the digest was keyed and ``key`` is missing (or vice versa).
    """
    if not approval.code_hash or not approval.code_salt:
        return False
    if (approval.code_alg == "hmac-sha256") != (key is not None):
        return None
    expected = hash_code(code, approval_id=approval.id, salt=approval.code_salt, key=key)
    return hmac.compare_digest(expected, approval.code_hash)


def decision_mac(
    approval: Approval, status: str, decided: float, by: str, key: bytes | None
) -> str | None:
    """Return the HMAC that authenticates a decision, or ``None`` without a key."""
    if key is None:
        return None
    fields = [approval.id, approval.session, approval.fingerprint, status, decided, by]
    return hmac.new(key, canonical_json(fields).encode(), hashlib.sha256).hexdigest()


def decision_is_authentic(approval: Approval, key: bytes | None) -> bool:
    """Return whether a stored approval carries a valid MAC (always true without a key)."""
    if key is None:
        return True
    if approval.decided is None or approval.decided_by is None or not approval.decision_mac:
        return False
    expected = decision_mac(approval, "approved", approval.decided, approval.decided_by, key)
    return hmac.compare_digest(expected or "", approval.decision_mac)


def approval_key_from_env(name: str = ENV_APPROVAL_KEY) -> bytes | None:
    """Return the approval key from ``name``, falling back to ``TOOLGUARD_AUDIT_KEY``."""
    value = os.environ.get(name) or os.environ.get("TOOLGUARD_AUDIT_KEY")
    return value.encode("utf-8") if value else None


@dataclass(frozen=True)
class ChallengeResult:
    """Answer to ``toolguard approve``: ``status`` is one of :data:`CHALLENGE_RESULTS`."""

    status: str
    approval: Approval | None
    attempts_left: int = 0


CHALLENGE_RESULTS = (
    "approved",
    "wrong",
    "locked",
    "expired",
    "not_pending",
    "no_code",
    "unverifiable",
)


def answer_challenge(
    store: Store,
    approval_id: str,
    code: str,
    *,
    by: str,
    settings: ChallengeSettings,
    now: float,
) -> ChallengeResult:
    """Approve ``approval_id`` if ``code`` matches; count failures and lock at the limit."""
    key = settings.key
    status, approval = store.answer_challenge(
        approval_id,
        check=lambda row: code_matches(row, code, key),
        now=now,
        max_attempts=settings.max_attempts,
        by=by,
        sign=lambda row, decided, who: decision_mac(row, "approved", decided, who, key),
    )
    left = 0
    if status == "wrong" and approval is not None:
        left = settings.max_attempts - approval.attempts - 1
    return ChallengeResult(status, approval, left)


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
