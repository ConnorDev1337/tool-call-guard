"""Core data types: actions, observations, evidence and decisions."""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


class Action(enum.IntEnum):
    """Outcome for a tool call, ordered so that ``max()`` picks the most restrictive."""

    ALLOW = 0
    CONFIRM = 1
    BLOCK = 2

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str | Action) -> Action:
        """Return the action named ``value`` (case-insensitive); raise ValueError if unknown."""
        if isinstance(value, Action):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown action {value!r} (expected allow, confirm or block)"
            ) from None


def canonical_json(value: Any) -> str:
    """Serialize ``value`` deterministically (sorted keys, no whitespace) for hashing."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def call_fingerprint(tool: str, args: Any) -> str:
    """Return the SHA-256 identity of one exact tool call; approvals are bound to it."""
    payload = canonical_json({"tool": tool, "args": args})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Indicator:
    """A concrete, attributable value extracted from text (URL, e-mail, IBAN, ...)."""

    kind: str
    value: str


@dataclass(frozen=True)
class Observation:
    """Data that entered the agent's context through a tool result or the user."""

    id: int
    session: str
    ts: float
    tool: str
    kind: str
    untrusted: bool
    private: bool
    trusted: bool
    text: str  # Normalized and size-capped; used for provenance matching
    indicators: tuple[Indicator, ...]
    digest: str

    @property
    def label(self) -> str:
        flags = [f for f, on in (("untrusted", self.untrusted), ("private", self.private)) if on]
        return f"{self.tool} [{self.kind}; {', '.join(flags) or 'trusted'}]"


@dataclass(frozen=True)
class Evidence:
    """Why an argument is attributed to an observation."""

    arg: str  # Dotted argument path, e.g. "to" or "destination.iban"
    method: str  # "indicator" | "verbatim" | "fragment" | "secret"
    matched: str  # Redacted excerpt of the matched value
    observation_id: int
    source: str  # Observation label
    endorsed: bool = False  # The value also appears in trusted (user) input


@dataclass(frozen=True)
class Reason:
    """A rule that fired, the action it demands and its evidence."""

    rule: str  # "tainted" | "untrusted_flow" | "private_flow" | "trifecta" | "protect" | ...
    action: Action
    message: str
    evidence: tuple[Evidence, ...] = ()


@dataclass
class Decision:
    """Outcome of evaluating one tool call; ``category`` is the matched sink, if any."""

    tool: str
    args: Any
    action: Action  # What the policy demands
    category: str | None = None
    reasons: list[Reason] = field(default_factory=list)
    mode: str = "enforce"
    effective: Action | None = None  # After monitor mode or approval
    approval_id: str | None = None
    approval_status: str | None = None  # "approved" | "denied" | "pending" | "delegated"
    approved_by: str | None = None

    def __post_init__(self) -> None:
        if self.effective is None:
            self.effective = self.action

    @property
    def fingerprint(self) -> str:
        return call_fingerprint(self.tool, self.args)

    @property
    def allowed(self) -> bool:
        return self.effective == Action.ALLOW

    def explain(self) -> str:
        """Return an explanation for humans and the model, without raw argument values."""
        head = f"toolguard: {self.action.label.upper()} {self.tool}"
        if self.category:
            head += f" (sink: {self.category})"
        if self.mode == "monitor" and self.action != Action.ALLOW:
            head += " [monitor mode: allowed anyway]"
        lines = [head]
        for reason in self.reasons:
            lines.append(f"- [{reason.rule}] {reason.message}")
            for ev in reason.evidence[:5]:
                endorsed = " (also in user input)" if ev.endorsed else ""
                match = f"arg '{ev.arg}' {ev.method} match {ev.matched!r}"
                lines.append(f"    {match} from {ev.source}{endorsed}")
        if self.approval_status == "pending" and self.approval_id:
            lines.append(
                f"- approval {self.approval_id} is pending; a human must run "
                f"'toolguard approve {self.approval_id}' in an interactive terminal, "
                "then the identical call can be retried"
            )
        elif self.approval_status:
            by = f" by {self.approved_by}" if self.approved_by else ""
            lines.append(f"- approval {self.approval_status}{by}")
        return "\n".join(lines)


class ToolBlocked(Exception):
    """Raised by guarded tools when the call is not allowed."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.explain())
        self.decision = decision
