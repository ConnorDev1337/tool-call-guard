"""Out-of-band notifiers that deliver one-time approval codes to a human.

A code must reach the person who approves, and nothing the model reads: never
hook output, tool results or MCP error text. Every notifier raises
:class:`NotifyError` when delivery fails, so the caller can fall back to the
next channel or, if none works, refuse the approval (fail closed). Error
messages never contain the code or a secret. Secrets (webhook signing key,
Telegram bot token) are read from environment variables at send time and are
never stored or logged.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

ENV_WEBHOOK_SECRET = "TOOLGUARD_WEBHOOK_SECRET"  # noqa: S105 - a variable name
ENV_TELEGRAM_TOKEN = "TOOLGUARD_TELEGRAM_TOKEN"  # noqa: S105 - a variable name
TELEGRAM_API = "https://api.telegram.org"
DEFAULT_TIMEOUT = 5.0  # Seconds; a hook process has little time to spare
TELEGRAM_LIMIT = 4096  # Characters per Telegram message


class NotifyError(Exception):
    """A notifier could not deliver a notice; the message is safe to log."""


class ConfigError(ValueError):
    """The notifier configuration is invalid."""


@dataclass(frozen=True)
class Notice:
    """What the approving human needs: the call, the evidence and the one-time code."""

    approval_id: str
    tool: str
    session: str
    code: str
    expires: float
    summary: str = ""
    args_preview: Any = None
    test: bool = False

    @property
    def title(self) -> str:
        if self.test:
            return "toolguard: test notification"
        return f"toolguard: approval {self.approval_id} for {self.tool}"

    def text(self, details: bool = True) -> str:
        """Return the notice as plain text; ``details`` adds the evidence and arguments."""
        if self.test:
            return "This is a test of the toolguard approval channel; no action is needed."
        expires = _dt.datetime.fromtimestamp(self.expires).isoformat(sep=" ", timespec="seconds")
        lines = [
            f"Approval {self.approval_id} requested for {self.tool} (session {self.session}).",
            f"One-time code: {self.code} (valid until {expires}).",
            f"Approve: toolguard approve {self.approval_id} (enter the code when asked).",
            f"Deny: toolguard deny {self.approval_id}. Never paste the code into the agent.",
        ]
        if details:
            lines += ["", self.summary]
            if self.args_preview is not None:
                preview = json.dumps(self.args_preview, ensure_ascii=False, default=str)
                lines.append(f"Arguments (redacted): {preview}")
        return "\n".join(lines).rstrip()

    def payload(self, details: bool = True) -> dict[str, Any]:
        """Return the notice as a JSON-serializable object (webhook body)."""
        body: dict[str, Any] = {
            "type": "toolguard.test" if self.test else "toolguard.approval",
            "approval_id": self.approval_id,
            "tool": self.tool,
            "session": self.session,
            "code": self.code,
            "expires": self.expires,
            "sent": time.time(),
            "approve_command": f"toolguard approve {self.approval_id}",
            "text": self.text(details),
        }
        if details:
            body.update(summary=self.summary, args=self.args_preview)
        return body


class Notifier(Protocol):
    """A channel that delivers notices to a human; ``name`` is recorded in the audit."""

    name: str

    def send(self, notice: Notice) -> None: ...


class CallbackNotifier:
    """Deliver notices through the embedding application's own channel."""

    def __init__(self, callback: Callable[[Notice], object], name: str = "callback") -> None:
        self.callback = callback
        self.name = name

    def send(self, notice: Notice) -> None:
        self.callback(notice)


# --------------------------------------------------------------------------- local channels


class FileNotifier:
    """Append notices to a file, FIFO or terminal device the operator watches.

    Put it where the agent cannot read it, e.g. a directory owned by another user.
    """

    def __init__(self, path: str, *, details: bool = True, name: str = "file") -> None:
        self.path = path
        self.details = details
        self.name = name

    def send(self, notice: Notice) -> None:
        stamp = _dt.datetime.now().isoformat(timespec="seconds")
        block = f"[{stamp}] {notice.title}\n{notice.text(self.details)}\n\n"
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                out.write(block)
        except OSError as exc:
            raise NotifyError(f"cannot write to {self.path}: {exc.strerror or exc}") from None


class TerminalNotifier:
    """Write notices to the controlling terminal (``/dev/tty`` or ``CONOUT$``).

    Suits an operator watching the guard's own terminal; anything that can read
    that terminal's scrollback (e.g. ``tmux capture-pane``) can read the code.
    """

    def __init__(
        self,
        opener: Callable[[], Any] | None = None,
        *,
        details: bool = True,
        name: str = "terminal",
    ) -> None:
        self.opener = opener
        self.details = details
        self.name = name

    def send(self, notice: Notice) -> None:
        opener = self.opener
        if opener is None:
            from .approvals import open_console

            opener = open_console
        with opener() as console:
            if console is None:
                raise NotifyError("no controlling terminal available")
            _, writer = console
            rule = "=" * 72
            writer.write(f"\n{rule}\n{notice.title}\n{notice.text(self.details)}\n{rule}\n")
            writer.flush()


_WINDOWS_TOAST = r"""
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.Encoding]::UTF8
$parts = [Console]::In.ReadToEnd() -split "`n", 2
try {
    $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
        [Windows.UI.Notifications.ToastTemplateType]::ToastText02)
    $nodes = $xml.GetElementsByTagName('text')
    $null = $nodes.Item(0).AppendChild($xml.CreateTextNode($parts[0]))
    $null = $nodes.Item(1).AppendChild($xml.CreateTextNode($parts[1]))
    $app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show($toast)
} catch {
    Add-Type -AssemblyName System.Windows.Forms
    $icon = New-Object System.Windows.Forms.NotifyIcon
    $icon.Icon = [System.Drawing.SystemIcons]::Warning
    $icon.Visible = $true
    $icon.ShowBalloonTip(30000, $parts[0], $parts[1], 'Warning')
    Start-Sleep -Seconds 4
    $icon.Dispose()
}
"""  # noqa: E501 - a WinRT type literal cannot be wrapped


def _applescript_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


class DesktopNotifier:
    """Show a desktop notification: Windows toast, macOS Notification Center or notify-send.

    Best effort: a toast cannot confirm that someone saw it, so configure another
    channel after it as a fallback. The text is passed on stdin where the platform
    allows it (PowerShell, osascript), not on the command line; ``notify-send`` only
    takes arguments, so on Linux the code is briefly visible in the process list to
    processes of the same user.
    """

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        details: bool = False,
        name: str = "desktop",
        platform: str | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self.timeout = timeout
        self.details = details
        self.name = name
        self.platform = platform or sys.platform
        self.runner = runner
        self.which = which

    def command(self, notice: Notice) -> tuple[list[str], str | None]:
        """Return the command line and the stdin text for this platform."""
        title, body = notice.title, notice.text(self.details)
        if self.platform == "win32":
            exe = self.which("powershell.exe") or self.which("powershell")
            if not exe:
                raise NotifyError("Windows PowerShell not found")
            argv = [exe, "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_TOAST]
            return argv, f"{title}\n{body}"
        if self.platform == "darwin":
            exe = self.which("osascript")
            if not exe:
                raise NotifyError("osascript not found")
            script = (
                f"display notification {_applescript_string(body)} "
                f'with title {_applescript_string(title)} sound name "default"'
            )
            return [exe, "-"], script
        exe = self.which("notify-send")
        if not exe:
            raise NotifyError("notify-send not found")
        return [exe, "--urgency=critical", "--app-name=toolguard", "--", title, body], None

    def send(self, notice: Notice) -> None:
        argv, stdin = self.command(notice)
        try:
            result = self.runner(
                argv,
                input=stdin,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self.timeout,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise NotifyError(f"desktop notification failed ({type(exc).__name__})") from None
        if result.returncode != 0:
            # stderr is not reported: it could echo the notice text.
            raise NotifyError(f"desktop notification failed (exit code {result.returncode})")


# --------------------------------------------------------------------------- HTTP channels


def is_loopback(host: str | None) -> bool:
    """Return whether ``host`` names this machine (``localhost`` or a loopback address)."""
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_url(url: str, where: str) -> str:
    """Return ``url`` if it is HTTPS, or HTTP to a loopback address; raise ConfigError."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and is_loopback(parts.hostname):
        return url
    raise ConfigError(f"{where}: URL must use https (plain http only to a loopback address)")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: they could move the code to another host or to plain HTTP."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise NotifyError("the endpoint answered with a redirect, which is not followed")


def _post_json(
    url: str, body: bytes, headers: Mapping[str, str], timeout: float
) -> tuple[int, bytes]:
    """POST ``body`` and return ``(status, response body)``; raise NotifyError."""
    handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
    if is_loopback(urllib.parse.urlsplit(url).hostname):
        handlers.append(urllib.request.ProxyHandler({}))  # Never send loopback via a proxy
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(  # noqa: S310 - the scheme is checked by check_url
        url, data=body, method="POST", headers={"Content-Type": "application/json", **headers}
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(65536) if exc.fp else b""
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise NotifyError(f"request failed ({type(exc).__name__}: {reason})") from None


def _secret(env: str, what: str) -> bytes:
    value = os.environ.get(env)
    if not value:
        raise NotifyError(f"{what}: environment variable {env} is not set")
    return value.encode("utf-8")


class WebhookNotifier:
    """POST the notice as JSON, signed with HMAC-SHA256 over the exact body.

    The signature is sent as ``X-Toolguard-Signature: sha256=<hex>``; the receiver
    recomputes it with the shared secret from ``secret_env`` and should reject old
    ``sent`` timestamps and repeated approval ids.
    """

    def __init__(
        self,
        url: str,
        *,
        secret_env: str = ENV_WEBHOOK_SECRET,
        timeout: float = DEFAULT_TIMEOUT,
        details: bool = True,
        name: str = "webhook",
    ) -> None:
        self.url = check_url(url, "webhook")
        self.secret_env = secret_env
        self.timeout = timeout
        self.details = details
        self.name = name

    def send(self, notice: Notice) -> None:
        secret = _secret(self.secret_env, "webhook")
        body = json.dumps(notice.payload(self.details), ensure_ascii=False, default=str).encode()
        signature = hmac.new(secret, body, hashlib.sha256).hexdigest()
        status, _ = _post_json(
            self.url, body, {"X-Toolguard-Signature": f"sha256={signature}"}, self.timeout
        )
        if not 200 <= status < 300:
            raise NotifyError(f"webhook answered HTTP {status}")


class TelegramNotifier:
    """Send the notice to a Telegram chat through the Bot API.

    The bot token is read from ``token_env`` at send time and never stored, logged
    or included in errors. ``api_url`` exists for self-hosted Bot API servers and
    tests.
    """

    def __init__(
        self,
        chat_id: str | int,
        *,
        token_env: str = ENV_TELEGRAM_TOKEN,
        api_url: str = TELEGRAM_API,
        timeout: float = DEFAULT_TIMEOUT,
        details: bool = True,
        name: str = "telegram",
    ) -> None:
        self.chat_id = str(chat_id)
        self.token_env = token_env
        self.api_url = check_url(api_url, "telegram api_url").rstrip("/")
        self.timeout = timeout
        self.details = details
        self.name = name

    def send(self, notice: Notice) -> None:
        token = _secret(self.token_env, "telegram").decode()
        text = f"{notice.title}\n\n{notice.text(self.details)}"
        if len(text) > TELEGRAM_LIMIT:
            text = text[: TELEGRAM_LIMIT - 20] + "\n[truncated]"
        body = json.dumps(
            {"chat_id": self.chat_id, "text": text, "disable_web_page_preview": True}
        ).encode()
        url = f"{self.api_url}/bot{urllib.parse.quote(token, safe=':')}/sendMessage"
        try:
            status, response = _post_json(url, body, {}, self.timeout)
        except NotifyError as exc:
            raise NotifyError(str(exc).replace(token, "***")) from None
        try:
            answer = json.loads(response or b"{}")
        except ValueError:
            answer = {}
        if status != 200 or not isinstance(answer, dict) or answer.get("ok") is not True:
            detail = str(answer.get("description", "")) if isinstance(answer, dict) else ""
            detail = detail.replace(token, "***")[:200]
            raise NotifyError(
                f"telegram answered HTTP {status}" + (f": {detail}" if detail else "")
            )


# --------------------------------------------------------------------------- configuration

_SECRET_KEYS = {"token", "bot_token", "secret", "password", "api_key", "key"}
_COMMON = {"type", "name", "details", "timeout"}
_FIELDS = {
    "desktop": set(),
    "terminal": set(),
    "file": {"path"},
    "webhook": {"url", "secret_env"},
    "telegram": {"chat_id", "token_env", "api_url"},
}
_REQUIRED = {"file": ("path",), "webhook": ("url",), "telegram": ("chat_id",)}


def _option(table: Mapping[str, Any], key: str, kind: type | tuple[type, ...], where: str) -> Any:
    value = table[key]
    if not isinstance(value, kind) or (isinstance(value, bool) and kind is not bool):
        raise ConfigError(f"{where}.{key}: wrong type")
    return value


def build_notifier(table: Mapping[str, Any], where: str = "notifier") -> Notifier:
    """Build a notifier from one ``[[notifier]]`` table of the approvals configuration."""
    kind = table.get("type")
    if kind not in _FIELDS:
        raise ConfigError(f"{where}.type must be one of {', '.join(sorted(_FIELDS))}")
    secrets_inline = sorted(set(table) & _SECRET_KEYS)
    if secrets_inline:
        raise ConfigError(
            f"{where}: {', '.join(secrets_inline)} must not be written in the configuration; "
            "secrets come from environment variables (token_env, secret_env)"
        )
    unknown = sorted(set(table) - _COMMON - _FIELDS[kind])
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)} for type {kind!r}")
    for key in _REQUIRED.get(kind, ()):
        if key not in table:
            raise ConfigError(f"{where}: type {kind!r} requires {key!r}")
    options: dict[str, Any] = {"name": str(table.get("name") or kind)}
    if "details" in table:
        options["details"] = _option(table, "details", bool, where)
    if "timeout" in table:
        timeout = _option(table, "timeout", (int, float), where)
        if not 0 < timeout <= 60:
            raise ConfigError(f"{where}.timeout must be between 0 and 60 seconds")
        if kind not in {"file", "terminal"}:
            options["timeout"] = float(timeout)
    try:
        if kind == "desktop":
            return DesktopNotifier(**options)
        if kind == "terminal":
            options.pop("timeout", None)
            return TerminalNotifier(**options)
        if kind == "file":
            return FileNotifier(str(_option(table, "path", str, where)), **options)
        if kind == "webhook":
            if "secret_env" in table:
                options["secret_env"] = _option(table, "secret_env", str, where)
            return WebhookNotifier(_option(table, "url", str, where), **options)
        if "token_env" in table:
            options["token_env"] = _option(table, "token_env", str, where)
        if "api_url" in table:
            options["api_url"] = _option(table, "api_url", str, where)
        return TelegramNotifier(_option(table, "chat_id", (str, int), where), **options)
    except ConfigError as exc:
        raise ConfigError(f"{where}: {exc}") from None


def deliver(notifiers: list[Notifier], notice: Notice) -> Iterator[tuple[str, str | None]]:
    """Try ``notifiers`` in order; yield ``(name, error)`` per attempt until one succeeds.

    ``error`` is ``None`` for the channel that delivered the notice. Unexpected
    exceptions are reported by type only, so their text cannot leak a secret.
    """
    for notifier in notifiers:
        try:
            notifier.send(notice)
        except NotifyError as exc:
            yield notifier.name, str(exc) or "delivery failed"
            continue
        except Exception as exc:
            yield notifier.name, f"delivery failed ({type(exc).__name__})"
            continue
        yield notifier.name, None
        return
