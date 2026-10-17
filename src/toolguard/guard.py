"""The guard: records what the agent has seen and decides on every tool call.

Integrations call :meth:`Guard.observe_user` for trusted input, :meth:`Guard.check`
before each tool call and :meth:`Guard.observe` with its result; :meth:`Guard.wrap`
does the last two for a plain callable.
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import time
from collections.abc import Callable
from typing import Any, TypeVar

from .approvals import ApprovalRequest, Approver, DenyApprover, apply_outcome
from .audit import AuditLog, key_from_env
from .model import Action, Decision, Observation, Reason, ToolBlocked
from .policy import Policy, iter_strings, select_args
from .provenance import extract_indicators, normalize, private_flows, untrusted_flows
from .redact import redact_args
from .store import Store

F = TypeVar("F", bound=Callable[..., Any])


def _labels(observations: list[Observation], limit: int = 3) -> str:
    unique = list(dict.fromkeys(o.label for o in observations))
    shown = ", ".join(unique[:limit])
    return shown + (f" (+{len(unique) - limit} more)" if len(unique) > limit else "")


class Guard:
    """Information-flow guard for one agent.

    Defaults to the ``balanced`` preset, the shared on-disk store, a fail-closed
    :class:`DenyApprover` and the audit key from ``TOOLGUARD_AUDIT_KEY``.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        store: Store | None = None,
        session: str = "default",
        approver: Approver | None = None,
        audit_key: bytes | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.policy = policy or Policy.preset("balanced")
        self.store = store or Store()
        self.session = session
        self.approver: Approver = approver or DenyApprover()
        self.audit = AuditLog(self.store, audit_key if audit_key is not None else key_from_env())
        self.clock = clock
        self._policy_logged = False

    # ------------------------------------------------------------------ ingestion

    def _log_policy(self, session: str) -> None:
        if not self._policy_logged:
            self._policy_logged = True
            self.audit.append(
                "policy",
                session,
                {"name": self.policy.name, "digest": self.policy.digest, "mode": self.policy.mode},
            )

    def _record(
        self,
        session: str,
        tool: str,
        content: Any,
        *,
        kind: str,
        untrusted: bool,
        private: bool,
        trusted: bool,
    ) -> Observation:
        raw = "\n".join(text for _, text in iter_strings(content))
        limit = self.policy.max_observation_chars
        observation = self.store.add_observation(
            session=session,
            ts=self.clock(),
            tool=tool,
            kind=kind,
            untrusted=untrusted,
            private=private,
            trusted=trusted,
            text=normalize(raw[: limit * 2])[:limit],
            indicators=extract_indicators(raw[: limit * 2]),
            digest=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        )
        self._log_policy(session)
        self.audit.append(
            "observation",
            session,
            {
                "id": observation.id,
                "tool": tool,
                "kind": kind,
                "untrusted": untrusted,
                "private": private,
                "trusted": trusted,
                "chars": len(raw),
                "truncated": len(raw) > limit,
                "indicators": len(observation.indicators),
                "digest": observation.digest,
            },
        )
        return observation

    def observe(
        self, tool: str, output: Any, args: Any = None, *, session: str | None = None
    ) -> Observation | None:
        """Record a tool result if the policy marks the tool as a source; else return ``None``."""
        match = self.policy.source_for(tool, args if args is not None else {})
        if match is None:
            return None
        return self._record(
            session or self.session,
            tool,
            output,
            kind=match.kind,
            untrusted=match.untrusted,
            private=match.private,
            trusted=False,
        )

    def observe_user(self, text: str, *, session: str | None = None) -> Observation | None:
        """Record trusted user input; values in it are endorsed, not attributed."""
        if not self.policy.endorse_user_input or not text.strip():
            return None
        return self._record(
            session or self.session,
            "user",
            text,
            kind="user",
            untrusted=False,
            private=False,
            trusted=True,
        )

    def reset(self, *, session: str | None = None, by: str = "api") -> int:
        """Forget a session's observations (its taint); return how many were removed."""
        session = session or self.session
        removed = self.store.clear_session(session)
        self.audit.append("reset", session, {"observations_removed": removed, "by": by})
        return removed

    # ------------------------------------------------------------------ decisions

    def evaluate(self, tool: str, args: Any = None, *, session: str | None = None) -> Decision:
        """Return the policy decision for a call, without approval handling or audit."""
        session = session or self.session
        args = args if args is not None else {}
        policy = self.policy
        reasons: list[Reason] = []
        for rule, paths in policy.protect_hits(tool, args):
            reasons.append(
                Reason("protect", rule.action, f"{rule.message} (argument {', '.join(paths)})")
            )

        sink = policy.sink_for(tool, args)
        if sink is None:
            action = max((r.action for r in reasons), default=Action.ALLOW)
            return Decision(tool, args, action, None, reasons, policy.mode)

        table = policy.actions_for(sink.category)
        since = self.clock() - policy.taint_ttl if policy.taint_ttl else None
        seen = self.store.observations(session, since)
        untrusted = [o for o in seen if o.untrusted]
        private = [o for o in seen if o.private]
        trusted = [o for o in seen if o.trusted]

        if untrusted:
            reasons.append(
                Reason(
                    "tainted",
                    table.tainted,
                    f"the session has read untrusted data from {_labels(untrusted)}",
                )
            )
        flows = untrusted_flows(select_args(args, sink.critical), untrusted, trusted)
        attributed = tuple(e for e in flows if not e.endorsed)
        endorsed = tuple(e for e in flows if e.endorsed)
        if attributed:
            names = ", ".join(dict.fromkeys(e.arg for e in attributed))
            reasons.append(
                Reason(
                    "untrusted_flow",
                    table.untrusted_flow,
                    f"critical argument(s) {names} carry data copied from an untrusted source",
                    attributed,
                )
            )
        if endorsed:
            names = ", ".join(dict.fromkeys(e.arg for e in endorsed))
            reasons.append(
                Reason(
                    "endorsed_flow",
                    Action.ALLOW,
                    f"argument(s) {names} also appear in the user's own input",
                    endorsed,
                )
            )
        # An argument already attributed to an untrusted source (e.g. the attacker's
        # address inside a private e-mail) is explained by that flow; do not report
        # it again as a leak of private data.
        attributed_args = {e.arg for e in attributed}
        leaks = tuple(
            e
            for e in private_flows(select_args(args, ("*",)), private)
            if e.arg not in attributed_args
        )
        if leaks:
            names = ", ".join(dict.fromkeys(e.arg for e in leaks))
            reasons.append(
                Reason(
                    "private_flow",
                    table.private_flow,
                    f"argument(s) {names} carry private data",
                    leaks,
                )
            )
        if sink.egress and untrusted and private:
            reasons.append(
                Reason(
                    "trifecta",
                    table.trifecta,
                    "untrusted input and private data are both in context and this action "
                    f"sends data out (private: {_labels(private)})",
                )
            )
        action = max((r.action for r in reasons), default=Action.ALLOW)
        return Decision(tool, args, action, sink.category, reasons, policy.mode)

    def check(
        self,
        tool: str,
        args: Any = None,
        *,
        session: str | None = None,
        approver: Approver | None = None,
    ) -> Decision:
        """Evaluate a call, ask for approval if required and audit the decision."""
        session = session or self.session
        decision = self.evaluate(tool, args, session=session)
        self._log_policy(session)
        if self.policy.mode == "monitor":
            decision.effective = Action.ALLOW
        elif decision.action == Action.CONFIRM:
            request = ApprovalRequest(
                session=session,
                tool=tool,
                fingerprint=decision.fingerprint,
                summary=decision.explain(),
                args_preview=redact_args(decision.args, 200),
            )
            apply_outcome(decision, (approver or self.approver).request(request))
        self.audit.append("decision", session, self.decision_record(decision))
        return decision

    @staticmethod
    def decision_record(decision: Decision) -> dict[str, Any]:
        """Return the audit representation of ``decision``, with arguments redacted."""
        return {
            "tool": decision.tool,
            "category": decision.category,
            "action": decision.action.label,
            "effective": decision.effective.label if decision.effective is not None else None,
            "mode": decision.mode,
            "fingerprint": decision.fingerprint,
            "args": redact_args(decision.args),
            "reasons": [
                {
                    "rule": r.rule,
                    "action": r.action.label,
                    "message": r.message,
                    "evidence": [
                        {
                            "arg": e.arg,
                            "method": e.method,
                            "matched": e.matched,
                            "observation": e.observation_id,
                            "source": e.source,
                            "endorsed": e.endorsed,
                        }
                        for e in r.evidence
                    ],
                }
                for r in decision.reasons
            ],
            "approval": {
                "status": decision.approval_status,
                "id": decision.approval_id,
                "by": decision.approved_by,
                "channel": decision.approval_channel,
            }
            if decision.approval_status
            else None,
        }

    # ------------------------------------------------------------------ wrapping

    def wrap(self, tool: str, *, observe_output: bool = True) -> Callable[[F], F]:
        """Return a decorator that checks each call and records its result.

        The wrapped function raises :class:`ToolBlocked` when a call is not allowed.
        """

        def decorator(fn: F) -> F:
            signature = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = signature.bind(*args, **kwargs)
                call_args = dict(bound.arguments)
                decision = self.check(tool, call_args)
                if not decision.allowed:
                    raise ToolBlocked(decision)
                result = fn(*args, **kwargs)
                if observe_output:
                    self.observe(tool, result, call_args)
                return result

            return wrapper  # type: ignore[return-value]

        return decorator
