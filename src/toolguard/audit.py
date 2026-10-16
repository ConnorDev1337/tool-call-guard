"""Tamper-evident, hash-chained audit log.

Each record stores the hash of the previous one, so editing, reordering or
deleting a record breaks the chain. With ``TOOLGUARD_AUDIT_KEY`` set, the chain
uses HMAC-SHA256 and cannot be recomputed without the key. Truncating the tail
is only detectable against an external anchor: the ``head`` hash printed by
``toolguard audit verify``, kept where the agent cannot write.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, TextIO

from .model import canonical_json
from .store import Store

ENV_KEY = "TOOLGUARD_AUDIT_KEY"
GENESIS = "0" * 64


class AuditError(Exception):
    """The audit key does not match the algorithm the log was created with."""


def key_from_env() -> bytes | None:
    """Return the HMAC key from ``TOOLGUARD_AUDIT_KEY``, or ``None`` if unset."""
    value = os.environ.get(ENV_KEY)
    return value.encode("utf-8") if value else None


@dataclass(frozen=True)
class VerifyReport:
    """Result of :meth:`AuditLog.verify`; ``head`` is the hash of the last valid record."""

    ok: bool
    records: int
    algorithm: str
    head: str
    error: str | None = None
    bad_seq: int | None = None


class AuditLog:
    """Hash chain of audit records in a :class:`Store`.

    The algorithm is fixed when the log is created; raises :class:`AuditError` if
    ``key`` does not match it.
    """

    def __init__(self, store: Store, key: bytes | None = None) -> None:
        self.store = store
        self.key = key
        algorithm = store.get_meta("audit_algorithm")
        if algorithm is None:
            algorithm = "hmac-sha256" if key else "sha256"
            store.set_meta("audit_algorithm", algorithm)
        if algorithm == "hmac-sha256" and key is None:
            raise AuditError(f"the audit log is HMAC-protected; set {ENV_KEY}")
        if algorithm == "sha256" and key is not None:
            raise AuditError(f"the audit log was created without a key; unset {ENV_KEY}")
        self.algorithm = algorithm

    def _digest(self, prev: str, body: str) -> str:
        message = f"{prev}\n{body}".encode()
        if self.key is not None:
            return hmac.new(self.key, message, hashlib.sha256).hexdigest()
        return hashlib.sha256(message).hexdigest()

    def append(self, event: str, session: str, data: dict[str, Any]) -> dict[str, Any]:
        """Append an event and return the stored record, including ``prev`` and ``hash``."""
        with self.store.transaction() as conn:
            row = conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (row["seq"] + 1, row["hash"]) if row else (1, GENESIS)
            record = {
                "seq": seq,
                "ts": _dt.datetime.now(_dt.UTC).isoformat(timespec="milliseconds"),
                "session": session,
                "event": event,
                "data": data,
            }
            body = canonical_json(record)
            digest = self._digest(prev, body)
            conn.execute(
                "INSERT INTO audit (seq, body, prev, hash) VALUES (?, ?, ?, ?)",
                (seq, body, prev, digest),
            )
        return {**record, "prev": prev, "hash": digest}

    def records(self, since: int = 0) -> Iterator[dict[str, Any]]:
        for row in self.store.iter_audit(since):
            yield {**json.loads(row["body"]), "prev": row["prev"], "hash": row["hash"]}

    def verify(self) -> VerifyReport:
        """Check the whole chain and report the first inconsistency."""
        prev, count = GENESIS, 0
        for row in self.store.iter_audit():
            count += 1
            seq = row["seq"]
            if seq != count:
                return VerifyReport(False, count, self.algorithm, prev, "sequence gap", seq)
            if row["prev"] != prev:
                return VerifyReport(False, count, self.algorithm, prev, "broken link", seq)
            try:
                if json.loads(row["body"]).get("seq") != seq:
                    return VerifyReport(
                        False, count, self.algorithm, prev, "sequence mismatch", seq
                    )
            except ValueError:
                return VerifyReport(False, count, self.algorithm, prev, "unreadable record", seq)
            if not hmac.compare_digest(self._digest(prev, row["body"]), row["hash"]):
                return VerifyReport(False, count, self.algorithm, prev, "hash mismatch", seq)
            prev = row["hash"]
        return VerifyReport(True, count, self.algorithm, prev)

    def export_jsonl(self, out: TextIO, since: int = 0) -> int:
        """Write the records after ``since`` as JSON Lines; return how many were written."""
        count = 0
        for record in self.records(since):
            out.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
        return count
