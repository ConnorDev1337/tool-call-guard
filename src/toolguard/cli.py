"""``toolguard`` command line.

Exit codes for ``check``: 0 allowed, 1 blocked or denied, 2 usage or configuration
error, 3 approval pending. ``approve`` exits with 0 when approved, 1 for a wrong,
expired or locked code and 2 for usage errors.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import json
import os
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .adapters import claude_code
from .adapters.mcp_proxy import McpProxy
from .approvals import (
    ApprovalConfig,
    Approver,
    QueueApprover,
    answer_challenge,
    open_console,
)
from .audit import AuditError, AuditLog, key_from_env
from .guard import Guard
from .notifiers import ConfigError, Notice, deliver
from .policy import Policy, PolicyError
from .store import Store, default_home

ENV_POLICY = "TOOLGUARD_POLICY"
ENV_SESSION = "TOOLGUARD_SESSION"


def _policy(args: argparse.Namespace) -> Policy:
    policy = Policy.load(getattr(args, "policy", None) or os.environ.get(ENV_POLICY) or None)
    if getattr(args, "monitor", False):
        policy = policy.with_mode("monitor")
    return policy


def _store(args: argparse.Namespace) -> Store:
    path = getattr(args, "db", None)
    return Store(path) if path else Store()


def _session(args: argparse.Namespace) -> str:
    return getattr(args, "session", None) or os.environ.get(ENV_SESSION) or "default"


def _guard(args: argparse.Namespace, **kwargs: Any) -> Guard:
    return Guard(_policy(args), store=_store(args), session=_session(args), **kwargs)


def _approval_config(args: argparse.Namespace) -> ApprovalConfig:
    return ApprovalConfig.load(getattr(args, "approvals", None))


def _queue(args: argparse.Namespace, guard: Guard) -> QueueApprover:
    """Return the out-of-band approval queue configured for ``guard``."""
    return QueueApprover.from_config(
        guard.store, _approval_config(args), audit=guard.audit, clock=guard.clock
    )


def _user() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def _load_json(text: str, what: str) -> Any:
    try:
        return json.loads(text)
    except ValueError as exc:
        raise SystemExit(f"error: {what} is not valid JSON: {exc}") from None


def _call_args(args: argparse.Namespace) -> Any:
    if args.args_file:
        return _load_json(Path(args.args_file).read_text(encoding="utf-8"), "--args-file")
    if args.args:
        return _load_json(args.args, "--args")
    return {}


# --------------------------------------------------------------------------- commands


def cmd_check(args: argparse.Namespace) -> int:
    guard = _guard(args)
    decision = guard.check(args.tool, _call_args(args), approver=_queue(args, guard))
    if args.json:
        record = guard.decision_record(decision)
        record["explanation"] = decision.explain()
        print(json.dumps(record, indent=2, ensure_ascii=False))
    else:
        print(decision.explain())
    if decision.allowed:
        return 0
    return 3 if decision.approval_status == "pending" else 1


def cmd_observe(args: argparse.Namespace) -> int:
    guard = _guard(args)
    content = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()
    if args.user:
        observation = guard.observe_user(content)
    else:
        observation = guard.observe(args.tool, content, _call_args(args))
    if observation is None:
        print(f"{args.tool or 'input'}: not a source under the current policy; nothing recorded")
    else:
        print(f"recorded observation {observation.id}: {observation.label}")
    return 0


def _require_human(action: str) -> bool:
    """Return whether stdin is a terminal; approvals and resets must not be scriptable."""
    if not sys.stdin.isatty():
        print(f"error: '{action}' requires an interactive terminal", file=sys.stderr)
        return False
    return True


def _confirm_on_console(prompt: str) -> bool:
    """Return whether the person at the controlling terminal typed ``yes``."""
    with open_console() as console:
        if console is None:
            print("error: no controlling terminal available", file=sys.stderr)
            return False
        reader, writer = console
        writer.write(prompt + " Type 'yes' to confirm: ")
        writer.flush()
        return reader.readline().strip().lower() == "yes"


def _decision_queue(args: argparse.Namespace) -> tuple[QueueApprover, ApprovalConfig]:
    """Return a queue on the state database (for audit and expiry) and the configuration."""
    store = _store(args)
    config = _approval_config(args)
    return QueueApprover(store, audit=AuditLog(store, key_from_env())), config


def cmd_approvals(args: argparse.Namespace) -> int:
    queue, _ = _decision_queue(args)
    store = queue.store
    now = time.time()
    queue.expire(now)
    rows = store.list_approvals(None if args.all else "pending")
    if not rows:
        print("No pending approvals." if not args.all else "No approvals.")
    for row in rows:
        created = _dt.datetime.fromtimestamp(row.created).isoformat(timespec="seconds")
        notes = []
        if row.channel:
            notes.append(f"code via {row.channel}")
        if row.status == "pending" and row.expires is not None:
            notes.append(f"expires in {max(0, int(row.expires - now))}s")
        if row.attempts:
            notes.append(f"{row.attempts} wrong code(s)")
        extra = f"  [{', '.join(notes)}]" if notes else ""
        print(f"{row.id}  {row.status:<13} {created}  {row.tool}  (session {row.session}){extra}")
        if args.verbose:
            print("    " + row.summary.replace("\n", "\n    "))
    return 0


def _ask_code(approval_id: str, channel: str | None) -> str | None:
    """Ask for the one-time code on the controlling terminal; ``None`` if there is none."""
    with open_console() as console:
        if console is None:
            return None
        reader, writer = console
        via = f" (sent via {channel})" if channel else ""
        writer.write(f"\nOne-time code for approval {approval_id}{via}: ")
        writer.flush()
        return reader.readline().strip()


_APPROVE_ERRORS = {
    "expired": "the code has expired; let the agent retry the call to get a new one",
    "not_pending": "the approval is no longer pending",
    "no_code": "this approval predates approval codes; let the agent retry the call",
    "unverifiable": "the code hash is keyed: set the approval key (TOOLGUARD_APPROVAL_KEY "
    "or the configured key_env) as when the approval was created",
}


def cmd_approve(args: argparse.Namespace) -> int:
    """Approve a pending call with the one-time code delivered out of band."""
    queue, config = _decision_queue(args)
    store = queue.store
    queue.expire(time.time())
    approval = store.get_approval(args.id)
    if approval is None or approval.status != "pending":
        print(f"error: no pending approval {args.id!r}", file=sys.stderr)
        return 2
    print(approval.summary)
    code = args.code
    if code is None:
        code = _ask_code(approval.id, approval.channel)
        if code is None:
            print(
                "error: no controlling terminal to ask for the code; use --code", file=sys.stderr
            )
            return 2
    if not code.strip():
        print("aborted")
        return 1
    by = f"cli:{_user()}"
    result = answer_challenge(
        store, approval.id, code, by=by, settings=config.settings, now=time.time()
    )
    session, base = approval.session, {"id": approval.id, "tool": approval.tool}
    if result.status == "approved":
        queue.record_event(session, **base, status="approved", by=by)
        print(f"{approval.id}: approved. The agent may now retry the identical call.")
        return 0
    if result.status == "wrong":
        queue.record_event(
            session, **base, status="failed_attempt", by=by, left=result.attempts_left
        )
        print(f"error: wrong code ({result.attempts_left} attempt(s) left)", file=sys.stderr)
        return 1
    if result.status == "locked":
        queue.record_event(session, **base, status="failed_attempt", by=by, left=0)
        queue.record_event(session, **base, status="locked", attempts=config.settings.max_attempts)
        print(f"error: wrong code; approval {approval.id} is now locked", file=sys.stderr)
        return 1
    if result.status == "expired":
        queue.record_event(session, **base, status="expired")
    print(f"error: {_APPROVE_ERRORS[result.status]}", file=sys.stderr)
    return 1 if result.status == "expired" else 2


def cmd_deny(args: argparse.Namespace) -> int:
    """Deny a pending call; no code is needed to refuse, but a terminal is."""
    if not _require_human("deny"):
        return 2
    queue, _ = _decision_queue(args)
    store = queue.store
    approval = store.get_approval(args.id)
    if approval is None or approval.status != "pending":
        print(f"error: no pending approval {args.id!r}", file=sys.stderr)
        return 2
    print(approval.summary)
    if not _confirm_on_console(f"\nDENY this call to {approval.tool}?"):
        print("aborted")
        return 1
    by = f"cli:{_user()}"
    if not store.decide_approval(approval.id, "denied", by, time.time()):
        print("error: approval was decided concurrently", file=sys.stderr)
        return 2
    queue.record_event(
        approval.session, id=approval.id, tool=approval.tool, status="denied", by=by
    )
    print(f"{approval.id}: denied.")
    return 0


def cmd_notifiers(args: argparse.Namespace) -> int:
    """Show the approval configuration and, with ``--test``, try every notifier."""
    config = _approval_config(args)
    settings = config.settings
    print(f"approvals configuration: {config.path or 'none'}")
    print(
        f"  codes: {settings.length} characters, valid {settings.code_ttl:g}s, "
        f"{settings.max_attempts} attempt(s), stored as {settings.algorithm}"
    )
    if not config.notifiers:
        print("  no notifier: queued approvals are refused (fail closed)")
        return 1 if args.test else 0
    failed = 0
    for notifier in config.notifiers:
        line = f"  - {notifier.name} ({type(notifier).__name__})"
        if args.test:
            notice = Notice("test", "-", "-", "", time.time(), test=True)
            ((_, error),) = deliver([notifier], notice)
            failed += error is not None
            line += f": {'FAILED, ' + error if error else 'sent'}"
        print(line)
    return 1 if failed else 0


def cmd_sessions(args: argparse.Namespace) -> int:
    rows = _store(args).sessions()
    if not rows:
        print("No sessions with recorded observations.")
    for row in rows:
        last = _dt.datetime.fromtimestamp(row.last).isoformat(timespec="seconds")
        flags = []
        if row.untrusted:
            flags.append(f"{row.untrusted} untrusted")
        if row.private:
            flags.append(f"{row.private} private")
        print(
            f"{row.session}  {row.observations} observation(s) [{', '.join(flags)}]  last {last}"
        )
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    if not _require_human("reset"):
        return 2
    if not _confirm_on_console(f"Reset the taint of session {args.session_id!r}?"):
        print("aborted")
        return 1
    guard = Guard(_policy(args), store=_store(args), session=args.session_id)
    removed = guard.reset(by="cli")
    print(f"session {args.session_id}: {removed} observation(s) removed")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    try:
        log = AuditLog(_store(args), key_from_env())
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.audit_command == "verify":
        report = log.verify()
        status = "OK" if report.ok else f"FAILED at seq {report.bad_seq}: {report.error}"
        print(f"audit chain {status} ({report.records} records, {report.algorithm})")
        print(f"head: {report.head}")
        return 0 if report.ok else 1
    if args.audit_command == "export":
        out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout  # noqa: SIM115
        try:
            count = log.export_jsonl(out, since=args.since)
        finally:
            if args.output:
                out.close()
        if args.output:
            print(f"exported {count} record(s) to {args.output}")
        return 0
    records = list(log.records())[-args.n :]
    for record in records:
        data = record["data"]
        summary = data.get("tool") or data.get("name") or data.get("id") or ""
        extra = ""
        if record["event"] == "decision":
            extra = f" {data.get('action')} -> {data.get('effective')}"
        print(f"{record['seq']:>6} {record['ts']} {record['event']:<11} {summary}{extra}")
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    try:
        policy = Policy.load(args.file or getattr(args, "policy", None))
    except PolicyError as exc:
        print(f"invalid policy: {exc}", file=sys.stderr)
        return 2
    print(f"policy {policy.name} (mode {policy.mode}, digest {policy.digest[:12]})")
    print(
        f"  {len(policy.sources)} source rule(s), {len(policy.sinks)} sink rule(s), "
        f"{len(policy.protect)} protect rule(s), taint_ttl={policy.taint_ttl:g}s"
    )
    print("  actions (tainted / untrusted_flow / private_flow / trifecta):")
    for category, table in sorted(policy.actions.items()):
        values = [table.tainted, table.untrusted_flow, table.private_flow, table.trifecta]
        line = f"    {category:<12} " + " / ".join(a.label for a in values)
        if table.directed_flow is not None and table.directed_flow != table.untrusted_flow:
            line += f"  (directed_flow {table.directed_flow.label})"
        print(line)
    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    ask_modes = frozenset(m.strip() for m in args.ask_modes.split(",") if m.strip())
    approver: Callable[[Guard], Approver] | None = None
    if args.oob_approvals:

        def approver(guard: Guard) -> Approver:
            return _queue(args, guard)

    return claude_code.main(
        lambda: _guard(args), ask_modes=ask_modes, annotate=args.annotate, approver=approver
    )


def cmd_install(args: argparse.Namespace) -> int:
    python = Path(sys.executable).as_posix()
    command = f'"{python}" -m toolguard hook claude-code'
    if args.policy:
        policy = Path(args.policy)
        spec = policy.resolve().as_posix() if policy.exists() else args.policy
        command += f' --policy "{spec}"'
    print(json.dumps(claude_code.settings_snippet(command), indent=2))
    print(
        "\n# Merge this into ~/.claude/settings.json (all projects) or .claude/settings.json.\n"
        "# The guard blocks agents from editing these files; review changes yourself.",
        file=sys.stderr,
    )
    return 0


def cmd_mcp_proxy(args: argparse.Namespace) -> int:
    command = list(args.server_command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("error: missing server command after --", file=sys.stderr)
        return 2
    guard = _guard(args)
    try:
        code = McpProxy(guard, args.server_name, command, queue=_queue(args, guard)).run()
    except OSError as exc:
        print(f"error: cannot start the MCP server {command[0]!r}: {exc}", file=sys.stderr)
        return 127
    # The client pump may still be blocked reading stdin, and a normal interpreter
    # shutdown would then abort while it holds the stdin lock. State is already
    # committed, so exit at once; a server killed by signal N exits with 128 + N.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code if code >= 0 else 128 - code)


def cmd_eval(args: argparse.Namespace) -> int:
    from .evaluation import main as eval_main

    return eval_main(args)


# --------------------------------------------------------------------------- parser


def _common(parser: argparse.ArgumentParser, *, session: bool = True) -> None:
    parser.add_argument(
        "--policy", help=f"preset name or TOML path (default: ${ENV_POLICY} or balanced)"
    )
    parser.add_argument(
        "--db", help=f"state database (default: ${{TOOLGUARD_HOME}}/guard.db, {default_home()})"
    )
    parser.add_argument(
        "--approvals",
        help="approvals configuration (default: $TOOLGUARD_APPROVALS_CONFIG or "
        "$TOOLGUARD_HOME/approvals.toml)",
    )
    if session:
        parser.add_argument("--session", help=f"session id (default: ${ENV_SESSION} or 'default')")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="toolguard",
        description="Information-flow guard between LLM agents and their tools.",
    )
    parser.add_argument("--version", action="version", version=f"toolguard {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("check", help="decide on one tool call (generic integration)")
    _common(p)
    p.add_argument("tool")
    p.add_argument("--args", help="tool arguments as JSON")
    p.add_argument("--args-file", help="file with the tool arguments as JSON")
    p.add_argument("--monitor", action="store_true", help="log only, never block")
    p.add_argument("--json", action="store_true", help="print the decision as JSON")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("observe", help="record a tool result (stdin or --file)")
    _common(p)
    p.add_argument("tool", nargs="?", default="")
    p.add_argument("--file", help="read the content from FILE instead of stdin")
    p.add_argument("--args", help="the call's arguments as JSON (for conditional sources)")
    p.add_argument("--args-file")
    p.add_argument("--user", action="store_true", help="content is trusted user input")
    p.set_defaults(func=cmd_observe)

    p = sub.add_parser("hook", help="run as an agent hook")
    p.add_argument("integration", choices=["claude-code"])
    _common(p, session=False)
    p.add_argument("--monitor", action="store_true", help="log only, never block")
    p.add_argument(
        "--ask-modes",
        default=",".join(sorted(claude_code.ASK_MODES)),
        help="permission modes in which CONFIRM becomes 'ask' (others deny)",
    )
    p.add_argument(
        "--annotate", action="store_true", help="tell the model when output is untrusted"
    )
    p.add_argument(
        "--oob-approvals",
        action="store_true",
        help="in permission modes that ask nobody, queue CONFIRM for an out-of-band approval "
        "with a one-time code instead of denying it",
    )
    p.set_defaults(func=cmd_hook)

    p = sub.add_parser("install", help="print hook configuration for an agent")
    p.add_argument("integration", choices=["claude-code"])
    p.add_argument("--policy")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("mcp-proxy", help="guard an MCP stdio server")
    _common(p)
    p.add_argument("--server-name", required=True, help="name used in mcp__<name>__<tool>")
    p.add_argument("--monitor", action="store_true", help="log only, never block")
    p.add_argument("server_command", nargs=argparse.REMAINDER, help="-- command [args...]")
    p.set_defaults(func=cmd_mcp_proxy)

    p = sub.add_parser("approvals", help="list approval requests")
    _common(p, session=False)
    p.add_argument("--all", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_approvals)

    p = sub.add_parser("approve", help="approve a pending request with its one-time code")
    _common(p, session=False)
    p.add_argument("id")
    p.add_argument(
        "--code", help="the code sent out of band (default: ask on the controlling terminal)"
    )
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("deny", help="deny a pending request (interactive terminal only)")
    _common(p, session=False)
    p.add_argument("id")
    p.set_defaults(func=cmd_deny)

    p = sub.add_parser("notifiers", help="show the approval notifiers; --test sends a test")
    _common(p, session=False)
    p.add_argument("--test", action="store_true", help="send a test notice through each one")
    p.set_defaults(func=cmd_notifiers)

    p = sub.add_parser("sessions", help="list sessions and their taint")
    _common(p, session=False)
    p.set_defaults(func=cmd_sessions)

    p = sub.add_parser("reset", help="forget a session's observations (interactive only)")
    _common(p, session=False)
    p.add_argument("session_id")
    p.set_defaults(func=cmd_reset)

    p = sub.add_parser("audit", help="inspect the audit log")
    audit_sub = p.add_subparsers(dest="audit_command", metavar="ACTION", required=True)
    db_parent = argparse.ArgumentParser(add_help=False)
    _common(db_parent, session=False)
    audit_sub.add_parser("verify", parents=[db_parent], help="verify the hash chain")
    tail = audit_sub.add_parser("tail", parents=[db_parent], help="show the last records")
    tail.add_argument("-n", type=int, default=20)
    export = audit_sub.add_parser("export", parents=[db_parent], help="export as JSON Lines")
    export.add_argument("-o", "--output")
    export.add_argument("--since", type=int, default=0, help="only records after this seq")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("policy", help="validate and summarize a policy")
    p.add_argument("file", nargs="?", help="TOML file or preset name (default: balanced)")
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("eval", help="run the attack/benign scenario benchmark")
    p.add_argument("paths", nargs="*", help="scenario files or directories")
    p.add_argument(
        "--policy", action="append", dest="policies", help="policy to compare (repeatable)"
    )
    p.add_argument("--json", action="store_true", help="print results as JSON")
    p.add_argument(
        "--markdown", action="store_true", help="print summary as Markdown tables (for the README)"
    )
    p.add_argument(
        "--toolset",
        metavar="FILE",
        help="TOML with the sources and sinks of the scenarios' tools (added to each policy)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="per-call decisions")
    p.set_defaults(func=cmd_eval)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError):
            stream.reconfigure(errors="backslashreplace")
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return int(args.func(args))
    except (PolicyError, AuditError, ConfigError) as exc:
        if args.command == "hook":
            raise  # The hook adapter applies its own fail-closed exit codes
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
