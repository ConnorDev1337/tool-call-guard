"""Notifier tests: local fake HTTP servers and a fake process runner, never the network."""

import contextlib
import hashlib
import hmac
import http.server
import io
import json
import subprocess
import threading

import pytest

from toolguard.notifiers import (
    CallbackNotifier,
    ConfigError,
    DesktopNotifier,
    FileNotifier,
    Notice,
    NotifyError,
    TelegramNotifier,
    TerminalNotifier,
    WebhookNotifier,
    build_notifier,
    check_url,
    deliver,
    is_loopback,
)

CODE = "K7QF-2M9X-HB4T"
NOTICE = Notice(
    approval_id="ab12cd34",
    tool="Bash",
    session="s1",
    code=CODE,
    expires=1_700_000_300.0,
    summary="toolguard: CONFIRM Bash (sink: shell)\n- [tainted] web page read",
    args_preview={"command": "make deploy"},
)
TOKEN = "123456:TEST-ONLY-not-a-real-token"


class FakeServer:
    """Loopback HTTP server that records requests and answers with a scripted reply."""

    def __init__(self):
        self.requests = []
        self.reply = (200, {"ok": True}, {})
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                owner.requests.append((self.path, dict(self.headers), self.rfile.read(length)))
                status, body, headers = owner.reply
                data = json.dumps(body).encode() if body is not None else b"not json"
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    fake = FakeServer()
    yield fake
    fake.close()


def test_notice_text_and_payload():
    text = NOTICE.text()
    assert CODE in text and "toolguard approve ab12cd34" in text and "make deploy" in text
    assert "Never paste the code into the agent" in text
    brief = NOTICE.text(details=False)
    assert CODE in brief and "make deploy" not in brief
    payload = NOTICE.payload(details=False)
    assert payload["code"] == CODE and "summary" not in payload
    assert NOTICE.payload()["args"] == {"command": "make deploy"}
    test = Notice("test", "-", "-", "", 0.0, test=True)
    assert "test" in test.title and "no action" in test.text()
    assert test.payload()["type"] == "toolguard.test"


def test_loopback_and_url_rules():
    assert is_loopback("localhost") and is_loopback("127.0.0.1") and is_loopback("::1")
    assert not is_loopback("10.0.0.1") and not is_loopback("example.com")
    assert not is_loopback(None)
    assert check_url("https://hooks.example/x", "w")
    assert check_url("http://127.0.0.1:8080/x", "w")
    for bad in ("http://hooks.example/x", "ftp://127.0.0.1/x", "https:///nohost"):
        with pytest.raises(ConfigError, match="https"):
            check_url(bad, "w")


def test_webhook_posts_signed_json(server, monkeypatch):
    monkeypatch.setenv("TEST_WEBHOOK_SECRET", "shared-secret")
    notifier = WebhookNotifier(server.url + "/hook", secret_env="TEST_WEBHOOK_SECRET")
    notifier.send(NOTICE)
    ((path, headers, body),) = server.requests
    assert path == "/hook" and headers["Content-Type"] == "application/json"
    expected = hmac.new(b"shared-secret", body, hashlib.sha256).hexdigest()
    assert headers["X-Toolguard-Signature"] == f"sha256={expected}"
    payload = json.loads(body)
    assert payload["code"] == CODE and payload["approval_id"] == "ab12cd34"
    assert payload["type"] == "toolguard.approval"


def test_webhook_failures_fail_closed(server, monkeypatch):
    notifier = WebhookNotifier(server.url, secret_env="TEST_WEBHOOK_SECRET")
    with pytest.raises(NotifyError, match="TEST_WEBHOOK_SECRET is not set"):
        notifier.send(NOTICE)
    assert server.requests == []  # Nothing is sent unsigned
    monkeypatch.setenv("TEST_WEBHOOK_SECRET", "s")
    server.reply = (500, {"error": "boom"}, {})
    with pytest.raises(NotifyError, match="HTTP 500"):
        notifier.send(NOTICE)
    server.reply = (302, {}, {"Location": "http://elsewhere.example/"})
    with pytest.raises(NotifyError, match="redirect"):
        notifier.send(NOTICE)
    closed = WebhookNotifier("http://127.0.0.1:9/", secret_env="TEST_WEBHOOK_SECRET", timeout=2)
    with pytest.raises(NotifyError, match="request failed") as failure:
        closed.send(NOTICE)
    assert CODE not in str(failure.value)
    with pytest.raises(ConfigError):
        WebhookNotifier("http://hooks.example/x")


def test_telegram_sends_message_without_leaking_the_token(server, monkeypatch):
    monkeypatch.setenv("TEST_TG_TOKEN", TOKEN)
    notifier = TelegramNotifier(42, token_env="TEST_TG_TOKEN", api_url=server.url + "/")
    notifier.send(NOTICE)
    ((path, _, body),) = server.requests
    assert path == f"/bot{TOKEN}/sendMessage"
    message = json.loads(body)
    assert message["chat_id"] == "42" and CODE in message["text"]
    assert message["disable_web_page_preview"] is True

    server.reply = (401, {"ok": False, "description": f"Unauthorized {TOKEN}"}, {})
    with pytest.raises(NotifyError) as failure:
        notifier.send(NOTICE)
    assert "HTTP 401" in str(failure.value) and TOKEN not in str(failure.value)
    server.reply = (200, {"ok": False}, {})
    with pytest.raises(NotifyError, match="HTTP 200"):
        notifier.send(NOTICE)
    server.reply = (200, None, {})
    with pytest.raises(NotifyError):
        notifier.send(NOTICE)
    server.reply = (200, ["not", "an", "object"], {})
    with pytest.raises(NotifyError):
        notifier.send(NOTICE)


def test_telegram_requires_token_and_truncates(server, monkeypatch):
    notifier = TelegramNotifier("7", token_env="TEST_TG_TOKEN", api_url=server.url)
    with pytest.raises(NotifyError, match="TEST_TG_TOKEN is not set"):
        notifier.send(NOTICE)
    monkeypatch.setenv("TEST_TG_TOKEN", TOKEN)
    long = Notice("id", "Bash", "s", CODE, 0.0, summary="x" * 10_000)
    notifier.send(long)
    text = json.loads(server.requests[-1][2])["text"]
    assert len(text) <= 4096 and text.endswith("[truncated]") and CODE in text
    unreachable = TelegramNotifier(
        "7", token_env="TEST_TG_TOKEN", api_url="http://127.0.0.1:9", timeout=2
    )
    with pytest.raises(NotifyError) as failure:
        unreachable.send(NOTICE)
    assert TOKEN not in str(failure.value)
    with pytest.raises(ConfigError):
        TelegramNotifier("7", api_url="http://api.telegram.example")


def test_file_notifier_appends_private_file(tmp_path):
    target = tmp_path / "operator" / "approvals.log"
    with pytest.raises(NotifyError, match="cannot write"):
        FileNotifier(str(target)).send(NOTICE)
    target.parent.mkdir()
    notifier = FileNotifier(str(target))
    notifier.send(NOTICE)
    notifier.send(NOTICE)
    content = target.read_text(encoding="utf-8")
    assert content.count(CODE) == 2 and "approval ab12cd34" in content


def test_terminal_notifier(monkeypatch):
    out = io.StringIO()

    @contextlib.contextmanager
    def console():
        yield io.StringIO(), out

    @contextlib.contextmanager
    def no_console():
        yield None

    TerminalNotifier(console).send(NOTICE)
    assert CODE in out.getvalue()
    with pytest.raises(NotifyError, match="no controlling terminal"):
        TerminalNotifier(no_console).send(NOTICE)
    from toolguard import approvals

    monkeypatch.setattr(approvals, "open_console", no_console)
    with pytest.raises(NotifyError):
        TerminalNotifier().send(NOTICE)  # Default opener: the real controlling terminal


class Runner:
    def __init__(self, returncode=0, error=None):
        self.calls = []
        self.returncode = returncode
        self.error = error

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.error:
            raise self.error
        return subprocess.CompletedProcess(argv, self.returncode, "", "secret stderr")


def which_all(name):
    return f"/usr/bin/{name}"


@pytest.mark.parametrize("platform", ["win32", "darwin", "linux"])
def test_desktop_notifier_per_platform(platform):
    runner = Runner()
    DesktopNotifier(platform=platform, runner=runner, which=which_all).send(NOTICE)
    ((argv, kwargs),) = runner.calls
    if platform == "win32":
        assert argv[0].endswith("powershell.exe") and "-NonInteractive" in argv
        assert "ToastNotificationManager" in argv[-1] and "NotifyIcon" in argv[-1]
        assert CODE not in " ".join(argv) and CODE in kwargs["input"]  # Code only on stdin
    elif platform == "darwin":
        assert argv[1:] == ["-"] and CODE in kwargs["input"]
        assert kwargs["input"].startswith("display notification")
    else:
        assert "notify-send" in argv[0] and "--" in argv and kwargs["input"] is None
        assert CODE in argv[-1]
    assert kwargs["timeout"] == 10.0 and kwargs["check"] is False


def test_desktop_escapes_applescript():
    runner = Runner()
    tricky = Notice('a"b', "T\\x", "s", CODE, 0.0)
    DesktopNotifier(platform="darwin", runner=runner, which=which_all).send(tricky)
    script = runner.calls[0][1]["input"]
    assert 'a\\"b' in script and "T\\\\x" in script


def test_desktop_failures_raise_without_leaking():
    def which_none(name):
        return None

    for platform, missing in (("win32", "PowerShell"), ("darwin", "osascript"), ("linux", "")):
        with pytest.raises(NotifyError, match=missing or "notify-send"):
            DesktopNotifier(platform=platform, runner=Runner(), which=which_none).send(NOTICE)
    failing = DesktopNotifier(platform="linux", runner=Runner(returncode=1), which=which_all)
    with pytest.raises(NotifyError, match="exit code 1") as failure:
        failing.send(NOTICE)
    assert "secret stderr" not in str(failure.value)
    timeout = Runner(error=subprocess.TimeoutExpired(["x"], 10))
    with pytest.raises(NotifyError, match="TimeoutExpired"):
        DesktopNotifier(platform="linux", runner=timeout, which=which_all).send(NOTICE)


def test_deliver_falls_back_in_order():
    seen = []

    def broken(notice):
        raise RuntimeError(f"leaky {notice.code}")

    def strict(notice):
        raise NotifyError("")

    chain = [
        CallbackNotifier(broken, "first"),
        CallbackNotifier(strict, "second"),
        CallbackNotifier(seen.append, "third"),
        CallbackNotifier(seen.append, "fourth"),
    ]
    attempts = list(deliver(chain, NOTICE))
    assert attempts == [
        ("first", "delivery failed (RuntimeError)"),
        ("second", "delivery failed"),
        ("third", None),
    ]
    assert seen == [NOTICE]  # Stops at the first channel that worked
    assert list(deliver([], NOTICE)) == []


def test_build_notifier_from_config(tmp_path):
    desktop = build_notifier({"type": "desktop", "timeout": 3})
    assert isinstance(desktop, DesktopNotifier) and desktop.timeout == 3.0
    assert isinstance(build_notifier({"type": "terminal", "timeout": 1}), TerminalNotifier)
    file = build_notifier({"type": "file", "path": str(tmp_path / "n.log"), "details": False})
    assert isinstance(file, FileNotifier) and file.details is False
    hook = build_notifier(
        {"type": "webhook", "url": "https://h.example/x", "secret_env": "S", "name": "ops"}
    )
    assert isinstance(hook, WebhookNotifier) and hook.name == "ops" and hook.secret_env == "S"
    tg = build_notifier(
        {"type": "telegram", "chat_id": 5, "token_env": "T", "api_url": "http://localhost:1"}
    )
    assert isinstance(tg, TelegramNotifier) and tg.chat_id == "5" and tg.token_env == "T"


@pytest.mark.parametrize(
    ("table", "message"),
    [
        ({"type": "pigeon"}, "type must be one of"),
        ({"type": "telegram", "chat_id": 1, "token": "x"}, "environment variables"),
        ({"type": "webhook", "url": "https://h.example", "secret": "x"}, "environment"),
        ({"type": "file", "path": "p", "colour": "red"}, "unknown key"),
        ({"type": "file"}, "requires 'path'"),
        ({"type": "webhook", "url": "http://h.example"}, "https"),
        ({"type": "file", "path": 3}, "wrong type"),
        ({"type": "desktop", "details": "yes"}, "wrong type"),
        ({"type": "desktop", "timeout": True}, "wrong type"),
        ({"type": "desktop", "timeout": 600}, "between 0 and 60"),
    ],
)
def test_build_notifier_rejects_bad_config(table, message):
    with pytest.raises(ConfigError, match=message):
        build_notifier(table)
