"""``toolguard`` command line.

Exit codes for ``check``: 0 allowed, 1 blocked or denied, 2 usage or configuration
error, 3 approval pending.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .adapters import claude_code
from .adapters.mcp_proxy import McpProxy
from .approvals import QueueApprover, open_console
from .audit import AuditError, AuditLog, key_from_env
from .guard import Guard
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
    approver = QueueApprover(guard.store)
    decision = guard.check(args.tool, _call_args(args), approver=approver)
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


def cmd_approvals(args: argparse.Namespace) -> int:
    store = _store(args)
    rows = store.list_approvals(None if args.all else "pending")
    if not rows:
        print("No pending approvals." if not args.all else "No approvals.")
    for row in rows:
        created = _dt.datetime.fromtimestamp(row.created).isoformat(timespec="seconds")
        print(f"{row.id}  {row.status:<9} {created}  {row.tool}  (session {row.session})")
        if args.verbose:
            print("    " + row.summary.replace("\n", "\n    "))
    return 0


def cmd_decide(args: argparse.Namespace, status: str) -> int:
    if not _require_human(status):
        return 2
    store = _store(args)
    approval = store.get_approval(args.id)
    if approval is None or approval.status != "pending":
        print(f"error: no pending approval {args.id!r}", file=sys.stderr)
        return 2
    print(approval.summary)
    verb = "APPROVE" if status == "approved" else "DENY"
    if not _confirm_on_console(f"\n{verb} this call to {approval.tool}?"):
        print("aborted")
        return 1
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    by = f"cli:{user}"
    if not store.decide_approval(approval.id, status, by, _dt.datetime.now().timestamp()):
        print("error: approval was decided concurrently", file=sys.stderr)
        return 2
    guard = Guard(_policy(args), store=store, session=approval.session)
    guard.audit.append(
        "approval", approval.session, {"id": approval.id, "status": status, "by": by}
    )
    print(
        f"{approval.id}: {status}. The agent may now retry the identical call."
        if status == "approved"
        else f"{approval.id}: denied."
    )
    return 0


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
        print(f"    {category:<12} " + " / ".join(a.label for a in values))
    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    ask_modes = frozenset(m.strip() for m in args.ask_modes.split(",") if m.strip())
    return claude_code.main(lambda: _guard(args), ask_modes=ask_modes, annotate=args.annotate)


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
    return McpProxy(guard, args.server_name, command).run()


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

    for name, status in (("approve", "approved"), ("deny", "denied")):
        p = sub.add_parser(name, help=f"{name} a pending request (interactive terminal only)")
        _common(p, session=False)
        p.add_argument("id")
        p.set_defaults(func=lambda a, s=status: cmd_decide(a, s))

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
    except (PolicyError, AuditError) as exc:
        if args.command == "hook":
            raise  # The hook adapter applies its own fail-closed exit codes
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
