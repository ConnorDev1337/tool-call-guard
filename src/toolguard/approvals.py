"""Human approval channels for decisions that require confirmation.

Approvals must come from a channel the agent cannot drive: a tool the model can
call, or text it can write, is never an approval. Hence the console channel uses
the controlling terminal rather than stdin/stdout, which may belong to the agent,
and a queued request can only be approved with a one-time code that a notifier
delivers out of band and the model never sees. Even a command the agent manages
to run (``toolguard approve`` behind an obfuscation that evades the protect
rules) fails without that code.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import secrets
import time
import tomllib
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, TextIO

from .audit import AuditLog
from .audit import key_from_env as audit_key_from_env
from .model import Action, Decision, Reason, canonical_json
from .notifiers import ConfigError, Notice, Notifier, build_notifier, deliver
from .store import Approval, Store, default_home

APPROVAL_TTL = 600.0  # Seconds an approval stays usable after a human decides
ENV_APPROVAL_KEY = "TOOLGUARD_APPROVAL_KEY"
ENV_APPROVALS_CONFIG = "TOOLGUARD_APPROVALS_CONFIG"

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


# --------------------------------------------------------------------------- configuration

_CHALLENGE_KEYS = {"code_ttl", "max_attempts", "length", "key_env"}


@dataclass(frozen=True)
class ApprovalConfig:
    """Challenge settings and notifiers, from ``approvals.toml``.

    The file is looked up in ``$TOOLGUARD_APPROVALS_CONFIG``, then in
    ``$TOOLGUARD_HOME/approvals.toml``. Without one there is no notifier, so queued
    approvals are impossible (fail closed). Secrets are never read from the file.
    """

    settings: ChallengeSettings = field(default_factory=ChallengeSettings)
    notifiers: tuple[Notifier, ...] = ()
    path: str | None = None

    @classmethod
    def load(cls, path: str | Path | None = None) -> ApprovalConfig:
        """Load the configuration; raise ConfigError if it is invalid or missing.

        An explicit ``path`` (or the environment variable) must exist; the default
        location is optional.
        """
        explicit = path or os.environ.get(ENV_APPROVALS_CONFIG)
        file = Path(explicit) if explicit else default_home() / "approvals.toml"
        if not file.is_file():
            if explicit:
                raise ConfigError(f"approvals configuration not found: {file}")
            return cls(ChallengeSettings(key=approval_key_from_env()))
        try:
            data = tomllib.loads(file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"{file}: {exc}") from None
        return cls.from_dict(data, path=str(file))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], path: str | None = None) -> ApprovalConfig:
        where = path or "approvals"
        unknown = sorted(set(data) - {"challenge", "notifier"})
        if unknown:
            raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}")
        challenge = data.get("challenge", {})
        if not isinstance(challenge, dict) or set(challenge) - _CHALLENGE_KEYS:
            raise ConfigError(
                f"{where}: [challenge] accepts only {', '.join(sorted(_CHALLENGE_KEYS))}"
            )
        key_env = challenge.get("key_env", ENV_APPROVAL_KEY)
        if not isinstance(key_env, str) or not key_env:
            raise ConfigError(f"{where}: challenge.key_env must name an environment variable")
        try:
            settings = ChallengeSettings(
                code_ttl=float(challenge.get("code_ttl", 300.0)),
                max_attempts=int(challenge.get("max_attempts", 5)),
                length=int(challenge.get("length", 12)),
                key=approval_key_from_env(key_env),
            )
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{where}: [challenge] {exc}") from None
        tables = data.get("notifier", [])
        if not isinstance(tables, list) or not all(isinstance(t, dict) for t in tables):
            raise ConfigError(f"{where}: notifiers are declared as [[notifier]] tables")
        notifiers = tuple(
            build_notifier(table, f"{where}: notifier[{index}]")
            for index, table in enumerate(tables)
        )
        names = [n.name for n in notifiers]
        if len(set(names)) != len(names):
            raise ConfigError(f"{where}: notifier names must be unique (set name = ...)")
        return cls(settings, notifiers, path)


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
    channel: str | None = None  # Notifier that delivered the approval code


def apply_outcome(decision: Decision, outcome: ApprovalOutcome) -> None:
    """Record an approval outcome on ``decision`` and set its effective action."""
    decision.approval_status = outcome.status
    decision.approval_id = outcome.approval_id
    decision.approved_by = outcome.by
    decision.approval_channel = outcome.channel
    decision.effective = Action.ALLOW if outcome.status == "approved" else Action.BLOCK
    if outcome.note and outcome.status != "approved":
        decision.reasons.append(Reason("approval", Action.BLOCK, outcome.note))


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
    """Queue requests for a human who approves with a one-time code sent out of band.

    Each new request gets a code from the CSPRNG that is handed only to the
    ``notifiers``, tried in order until one delivers it; the store keeps a hash. The
    human runs ``toolguard approve <id>`` and enters the code. If no notifier
    delivers it, the request is closed as undeliverable and denied (fail closed).
    The agent retries the identical call to use an approval, which is bound to the
    call fingerprint, single use and valid for ``ttl`` seconds after the decision.
    Events go to ``audit`` (by default the log of ``store`` with the key from the
    environment); they record channels, never codes.
    """

    def __init__(
        self,
        store: Store,
        ttl: float = APPROVAL_TTL,
        clock: Callable[[], float] = time.time,
        *,
        notifiers: Sequence[Notifier] = (),
        settings: ChallengeSettings | None = None,
        audit: AuditLog | None = None,
    ):
        self.store = store
        self.ttl = ttl
        self.clock = clock
        self.notifiers = list(notifiers)
        self.settings = settings or ChallengeSettings()
        self._audit = audit

    @classmethod
    def from_config(
        cls,
        store: Store,
        config: ApprovalConfig,
        *,
        audit: AuditLog | None = None,
        clock: Callable[[], float] = time.time,
    ) -> QueueApprover:
        return cls(
            store, clock=clock, notifiers=config.notifiers, settings=config.settings, audit=audit
        )

    @property
    def audit(self) -> AuditLog:
        if self._audit is None:
            self._audit = AuditLog(self.store, audit_key_from_env())
        return self._audit

    def _event(self, session: str, **data: Any) -> None:
        self.audit.append("approval", session, data)

    def expire(self, now: float) -> None:
        """Close pending approvals whose code has expired, recording each one."""
        for approval in self.store.expire_approvals(now):
            self._event(approval.session, id=approval.id, status="expired", tool=approval.tool)

    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        now = self.clock()
        self.expire(now)
        latest = self.store.latest_approval(req.fingerprint, req.session)
        if latest is not None:
            fresh = latest.decided is not None and now - latest.decided <= self.ttl
            if latest.status == "approved" and fresh:
                authentic = decision_is_authentic(latest, self.settings.key)
                if self.store.consume_approval(latest.id):
                    if authentic:
                        return ApprovalOutcome(
                            "approved",
                            by=latest.decided_by,
                            approval_id=latest.id,
                            channel=latest.channel,
                        )
                    self._event(
                        req.session,
                        id=latest.id,
                        status="rejected",
                        tool=req.tool,
                        reason="the decision has no valid MAC",
                    )
                    return ApprovalOutcome(
                        "denied",
                        approval_id=latest.id,
                        note="the stored approval failed its integrity check (not made with "
                        "the approval key); a new approval is needed",
                    )
            if latest.status in {"denied", "locked"} and fresh:
                note = None
                if latest.status == "locked":
                    note = f"approval {latest.id} was locked after too many wrong codes"
                return ApprovalOutcome(
                    "denied", by=latest.decided_by, approval_id=latest.id, note=note
                )
            if latest.status == "pending" and latest.code_hash:
                return ApprovalOutcome("pending", approval_id=latest.id, channel=latest.channel)
            if latest.status == "pending" and self.store.close_approval(latest.id, "expired", now):
                # Created before approvals required a code: it can never be approved.
                self._event(req.session, id=latest.id, status="expired", tool=req.tool)
        return self._create(req, now)

    def _create(self, req: ApprovalRequest, now: float) -> ApprovalOutcome:
        settings = self.settings
        approval_id = secrets.token_hex(4)
        code = new_code(settings.length)
        salt = secrets.token_hex(16)
        approval = self.store.create_approval(
            session=req.session,
            fingerprint=req.fingerprint,
            tool=req.tool,
            summary=req.summary,
            now=now,
            expires=now + settings.code_ttl,
            code_hash=hash_code(code, approval_id=approval_id, salt=salt, key=settings.key),
            code_salt=salt,
            code_alg=settings.algorithm,
            approval_id=approval_id,
        )
        self._event(
            req.session,
            id=approval.id,
            status="created",
            tool=req.tool,
            fingerprint=req.fingerprint,
            expires=approval.expires,
            code_alg=settings.algorithm,
        )
        notice = Notice(
            approval.id,
            req.tool,
            req.session,
            code,
            now + settings.code_ttl,
            req.summary,
            req.args_preview,
        )
        failed = []
        for channel, error in deliver(self.notifiers, notice):
            if error is None:
                self.store.set_approval_channel(approval.id, channel)
                self._event(req.session, id=approval.id, status="notified", channel=channel)
                return ApprovalOutcome("pending", approval_id=approval.id, channel=channel)
            failed.append(channel)
            self._event(
                req.session, id=approval.id, status="notify_failed", channel=channel, error=error
            )
        self.store.close_approval(approval.id, "undeliverable", now)
        self._event(req.session, id=approval.id, status="undeliverable", channels=failed)
        why = (
            "the approval code could not be delivered out of band"
            if self.notifiers
            else "no out-of-band notifier is configured for approval codes"
        )
        return ApprovalOutcome(
            "denied", approval_id=approval.id, note=f"{why}, so nobody can approve this call"
        )


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
