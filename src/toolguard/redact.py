"""Redaction for anything written to the audit log or shown in explanations.

Audit records outlive sessions and may be shipped elsewhere, so argument
values are masked when they look like credentials and truncated otherwise.
Each truncated or masked value keeps a short SHA-256 prefix so identical values
can still be correlated across records.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

_KNOWN_SECRET = re.compile(
    r"sk-ant-[A-Za-z0-9_\-]{16,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_\-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}"
    r"|xox[abposr]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{35}|[rs]k_live_[A-Za-z0-9]{16,}"
    r"|eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
    r"|-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?"
    r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)"
)
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_\-.])(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|authorization|"
    r"auth|cookie|private[_\-]?key|credential|session)(?:$|[_\-.])"
)
_URL_CREDENTIALS = re.compile(r"(?<=://)([^/\s:@]+):([^/\s@]+)@")


def short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def mask_secrets(text: str) -> str:
    text = _KNOWN_SECRET.sub(lambda m: f"[secret:{short_hash(m.group())}]", text)
    return _URL_CREDENTIALS.sub(lambda m: f"{m.group(1)}:****@", text)


def redact_value(value: str, limit: int = 500, *, force: bool = False) -> str:
    """Mask credentials; truncate long values; ``force`` hides the value entirely."""
    if force:
        return f"[redacted:{short_hash(value)}]"
    masked = mask_secrets(value)
    if len(masked) > limit:
        return f"{masked[:limit]}...[{len(value)} chars, sha256:{short_hash(value)}]"
    return masked


def redact_args(value: Any, limit: int = 500, _key: str = "") -> Any:
    """Deep copy of tool arguments that is safe to persist."""
    if isinstance(value, dict):
        return {str(k): redact_args(v, limit, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_args(v, limit, _key) for v in value]
    if isinstance(value, str):
        if _key and _SENSITIVE_KEY.search(_key) and value:
            return f"[redacted:{short_hash(value)}]"
        return redact_value(value, limit)
    return value
