"""Replay hook payloads captured from a real Claude Code 2.1.302 session (Windows, ``-p``)."""

import copy
import json
import os
import subprocess
import sys

import pytest

from conftest import FIXTURES
from toolguard.adapters.claude_code import handle_event

LIVE = json.loads((FIXTURES / "claude_code_2_1_302.json").read_text(encoding="utf-8"))
EVENTS = LIVE["events"]
WEB_SESSION = EVENTS["post_webfetch"]["session_id"]


def live(name, **changes):
    event = copy.deepcopy(EVENTS[name])
    event.update(changes)
    return event


def decision_of(result):
    if not result.stdout:
        return None
    output = json.loads(result.stdout)["hookSpecificOutput"]
    assert output["hookEventName"] == "PreToolUse"
    return output["permissionDecision"], output["permissionDecisionReason"]


def test_fixture_is_sanitized():
    assert LIVE["claude_code_version"] == "2.1.302"
    assert all(e["session_id"].startswith("0000000") for e in EVENTS.values())
    assert {e["cwd"] for e in EVENTS.values()} == {"C:\\Users\\user\\project"}


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("default", "ask"),
        ("acceptEdits", "ask"),
        ("plan", "ask"),
        ("bypassPermissions", "deny"),
        ("dontAsk", "deny"),
        ("auto", "deny"),
    ],
)
def test_shell_after_webfetch_per_permission_mode(make_guard, mode, expected):
    # Permission modes as Claude Code reports them (`--permission-mode manual` arrives as
    # "default").
    guard = make_guard()
    assert handle_event(guard, live("pre_bash", permission_mode=mode)).stdout is None
    handle_event(guard, live("pre_webfetch", permission_mode=mode))
    handle_event(guard, live("post_webfetch", permission_mode=mode))
    decision, reason = decision_of(handle_event(guard, live("pre_bash", permission_mode=mode)))
    assert decision == expected
    assert "untrusted data from WebFetch" in reason


def test_file_edits_after_webfetch_are_allowed(make_guard):
    guard = make_guard()
    handle_event(guard, live("post_webfetch"))
    for name in ("pre_write", "pre_edit", "pre_read"):
        assert handle_event(guard, live(name, session_id=WEB_SESSION)).stdout is None
    for name in ("post_write", "post_edit", "post_read", "post_bash"):
        assert handle_event(guard, live(name, session_id=WEB_SESSION)).stdout is None
    executed = [r["data"]["tool"] for r in guard.audit.records() if r["event"] == "executed"]
    assert executed == ["WebFetch", "Write", "Edit", "Bash"]


@pytest.mark.parametrize(
    "name",
    ["pre_bash_toolguard", "pre_powershell_toolguard", "pre_write_settings", "pre_monitor"],
)
def test_self_protection_on_live_payloads(make_guard, name):
    decision, reason = decision_of(handle_event(make_guard(), live(name)))
    assert decision == "deny" and "[protect]" in reason


def test_monitor_is_gated_like_a_shell(make_guard):
    guard = make_guard()
    monitor = live("pre_monitor", session_id=WEB_SESSION)
    monitor["tool_input"]["command"] = "tail -f build.log"
    assert handle_event(guard, monitor).stdout is None
    handle_event(guard, live("post_webfetch"))
    decision, reason = decision_of(handle_event(guard, monitor))
    assert decision == "ask" and "sink: shell" in reason


def test_failed_bash_is_audited_as_executed(make_guard):
    guard = make_guard()
    assert handle_event(guard, live("post_bash_failure")).stdout is None
    record = list(guard.audit.records())[-1]
    assert record["event"] == "executed"
    assert record["data"]["tool"] == "Bash" and record["data"]["failed"] is True


def test_resume_keeps_taint_and_clear_starts_a_new_session(make_guard):
    # /clear ends the session (SessionEnd reason "clear") and starts a new session id
    # (SessionStart source "clear"); the old transcript, and its taint, can be resumed.
    guard = make_guard()
    handle_event(guard, live("post_webfetch"))
    assert handle_event(guard, live("session_start_resume")).stdout is None
    assert decision_of(handle_event(guard, live("pre_bash")))[0] == "ask"
    handle_event(guard, live("session_end_clear"))
    handle_event(guard, live("session_start_clear"))
    new_session = EVENTS["session_start_clear"]["session_id"]
    assert new_session != WEB_SESSION
    assert handle_event(guard, live("pre_bash", session_id=new_session)).stdout is None
    assert decision_of(handle_event(guard, live("pre_bash")))[0] == "ask"


@pytest.mark.parametrize(
    "name", ["session_start_startup", "permission_request", "session_end_clear"]
)
def test_other_live_events_are_ignored(make_guard, name):
    result = handle_event(make_guard(), live(name))
    assert result.exit_code == 0 and result.stdout is None


def test_live_payloads_through_the_hook_process(tmp_path):
    # Raw UTF-8 bytes as Claude Code sends them, with a non-UTF-8 locale (Windows).
    env = {
        **os.environ,
        "TOOLGUARD_HOME": str(tmp_path / "home"),
        "PYTHONIOENCODING": "cp1252",
        "PYTHONUTF8": "0",
    }

    def call(event):
        return subprocess.run(
            [sys.executable, "-m", "toolguard", "hook", "claude-code"],
            input=json.dumps(event, ensure_ascii=False).encode("utf-8"),
            capture_output=True,
            env=env,
            check=False,
        )

    for name in ("user_prompt_submit", "pre_write", "post_read", "post_webfetch"):
        result = call(live(name))
        assert (result.returncode, result.stdout) == (0, b""), result.stderr
    result = call(live("pre_bash"))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
