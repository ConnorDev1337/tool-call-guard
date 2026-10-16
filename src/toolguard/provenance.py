"""Provenance: does a tool argument carry data that came from a given source?

The guard cannot see inside the model, so attribution is evidence-based:

* **indicator** - a concrete value (URL, domain, e-mail, IBAN, crypto address,
  phone, IP) in the argument also appears in the source text;
* **verbatim** - the whole (normalized) argument appears in the source text;
* **fragment** - a run of >= 4 consecutive tokens (>= 20 chars) of the
  argument appears in the source text (e.g. a copied shell command);
* **secret** - a high-entropy token of the argument appears in a private
  source (keys, tokens, passwords).

This is sound only for data that is copied, not paraphrased; the coarse
session-level "tainted" rule exists to cover the rest.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from .model import Evidence, Indicator, Observation
from .redact import redact_value

MIN_VERBATIM = 8
FRAGMENT_TOKENS = 4
FRAGMENT_MIN_CHARS = 20
MAX_FRAGMENTS = 400
SECRET_MIN_LEN = 16
SECRET_MIN_ENTROPY = 3.3

_ZERO_WIDTH = dict.fromkeys(
    [0x00AD, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, *range(0x202A, 0x202F), *range(0x2066, 0x206A)]
)
_WS = re.compile(r"\s+")
_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s<>\"'`)\]}]+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
_BTC = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_PHONE = re.compile(r"(?<![\w+])\+\d[\d ()./-]{7,18}\d\b")
# Secret-shaped runs: base64/base64url/hex alphabets. '=', '.', ':' and '@' split
# tokens so a key inside "k=<key>" or a JWT segment is still found on its own.
_TOKEN = re.compile(rf"[A-Za-z0-9+/_\-]{{{SECRET_MIN_LEN},}}")
_TRAILING = ".,;:!?'\""


def normalize(text: str) -> str:
    """Canonical text for matching: NFKC, no invisible chars, lowercase, single spaces."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return _WS.sub(" ", text).strip().lower()


def _iban_valid(value: str) -> bool:
    compact = value.replace(" ", "")
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def extract_indicators(text: str) -> tuple[Indicator, ...]:
    """Attributable values in ``text`` (deduplicated, normalized)."""
    found: dict[tuple[str, str], None] = {}

    def add(kind: str, value: str) -> None:
        found[(kind, value)] = None

    url_spans = []
    for match in _URL.finditer(text):
        url_spans.append(match.span())
        url = match.group().rstrip(_TRAILING)
        add("url", url.lower())
        host = re.sub(r"^[a-z]+://", "", url.lower()).split("/")[0].split("?")[0]
        host = host.rsplit("@", 1)[-1].split(":")[0]
        if "." in host:
            add("domain", host.removeprefix("www."))
    for match in _EMAIL.finditer(text):
        if any(start <= match.start() < end for start, end in url_spans):
            continue  # "user:pass@host" inside a URL is not an address
        email = match.group().lower()
        add("email", email)
        add("domain", email.split("@", 1)[1])
    for match in _IPV4.finditer(text):
        add("ip", match.group())
    for match in _IBAN.finditer(text):
        if _iban_valid(match.group()):
            add("iban", match.group().replace(" ", ""))
    for match in _BTC.finditer(text):
        add("crypto", match.group())
    for match in _ETH.finditer(text):
        add("crypto", match.group().lower())
    for match in _PHONE.finditer(text):
        digits = "+" + re.sub(r"\D", "", match.group())
        if 9 <= len(digits) <= 16:
            add("phone", digits)
    return tuple(Indicator(kind, value) for kind, value in found)


def _entropy(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def secret_tokens(text: str) -> set[str]:
    """High-entropy tokens that look like keys, tokens or passwords."""
    tokens = set()
    for match in _TOKEN.finditer(text):
        token = match.group().strip("-/")
        if len(token) < SECRET_MIN_LEN:
            continue
        has_digit = any(c.isdigit() for c in token)
        has_alpha = any(c.isalpha() for c in token)
        if has_digit and has_alpha and _entropy(token) >= SECRET_MIN_ENTROPY:
            tokens.add(token)
    return tokens


def _fragments(normalized: str) -> list[str]:
    tokens = normalized.split(" ")
    if len(tokens) < FRAGMENT_TOKENS:
        return []
    out = []
    for i in range(len(tokens) - FRAGMENT_TOKENS + 1):
        piece = " ".join(tokens[i : i + FRAGMENT_TOKENS])
        if len(piece) >= FRAGMENT_MIN_CHARS:
            out.append(piece)
        if len(out) >= MAX_FRAGMENTS:
            break
    return out


@dataclass(frozen=True)
class _Hit:
    method: str
    matched: str
    observation: Observation


def _match_value(value: str, observations: Iterable[Observation]) -> _Hit | None:
    """Strongest attribution of one argument value to one of ``observations``."""
    observations = list(observations)
    if not observations:
        return None
    for indicator in extract_indicators(value):
        if indicator.kind == "domain":
            continue  # domains are reported through their URL/e-mail; too coarse alone
        for obs in observations:
            if indicator in obs.indicators:
                return _Hit("indicator", indicator.value, obs)
    norm = normalize(value)
    if len(norm) >= MIN_VERBATIM:
        for obs in observations:
            if norm in obs.text:
                return _Hit("verbatim", norm, obs)
    for piece in _fragments(norm):
        for obs in observations:
            if piece in obs.text:
                return _Hit("fragment", piece, obs)
    return None


def _endorsed(matched: str, trusted: list[Observation]) -> bool:
    return any(
        matched in obs.text or any(i.value == matched for i in obs.indicators) for obs in trusted
    )


def untrusted_flows(
    values: Iterable[tuple[str, str]],
    untrusted: list[Observation],
    trusted: list[Observation],
) -> list[Evidence]:
    """Evidence that argument values were copied from untrusted observations."""
    evidence = []
    for path, value in values:
        hit = _match_value(value, untrusted)
        if hit is None:
            continue
        evidence.append(
            Evidence(
                arg=path,
                method=hit.method,
                matched=redact_value(hit.matched, 80),
                observation_id=hit.observation.id,
                source=hit.observation.label,
                endorsed=_endorsed(hit.matched, trusted),
            )
        )
    return evidence


def private_flows(values: Iterable[tuple[str, str]], private: list[Observation]) -> list[Evidence]:
    """Evidence that argument values carry private data (secrets or copied text)."""
    if not private:
        return []
    evidence = []
    for path, value in values:
        hit: _Hit | None = None
        for token in sorted(secret_tokens(value), key=len, reverse=True):
            obs = next((o for o in private if token.lower() in o.text), None)
            if obs is not None:
                hit = _Hit("secret", token, obs)
                break
        if hit is None:
            norm = normalize(value)
            if len(norm) >= FRAGMENT_MIN_CHARS:
                obs = next((o for o in private if norm in o.text), None)
                hit = _Hit("verbatim", norm, obs) if obs else None
            if hit is None:
                for piece in _fragments(norm):
                    obs = next((o for o in private if piece in o.text), None)
                    if obs is not None:
                        hit = _Hit("fragment", piece, obs)
                        break
        if hit is not None:
            evidence.append(
                Evidence(
                    arg=path,
                    method=hit.method,
                    matched=redact_value(hit.matched, 80, force=hit.method == "secret"),
                    observation_id=hit.observation.id,
                    source=hit.observation.label,
                )
            )
    return evidence
