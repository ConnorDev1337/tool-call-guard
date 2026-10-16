"""SQLite state shared by every process that guards the same agent.

One database holds the observations (what untrusted/private data each session
has seen), pending/decided approvals and the audit chain. SQLite gives
cross-process locking for free, which matters because one agent may talk to
several MCP proxies and hook invocations at once.

The database contains copies of untrusted and private content; it is created
with owner-only permissions where the OS supports it.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .model import Indicator, Observation

ENV_HOME = "TOOLGUARD_HOME"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session TEXT NOT NULL,
    ts REAL NOT NULL,
    tool TEXT NOT NULL,
    kind TEXT NOT NULL,
    untrusted INTEGER NOT NULL,
    private INTEGER NOT NULL,
    trusted INTEGER NOT NULL,
    text TEXT NOT NULL,
    indicators TEXT NOT NULL,
    digest TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS observations_session ON observations (session, ts);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    session TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    tool TEXT NOT NULL,
    summary TEXT NOT NULL,
    status TEXT NOT NULL,
    created REAL NOT NULL,
    decided REAL,
    decided_by TEXT
);
CREATE INDEX IF NOT EXISTS approvals_fingerprint ON approvals (fingerprint, session);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY,
    body TEXT NOT NULL,
    prev TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def default_home() -> Path:
    override = os.environ.get(ENV_HOME)
    return Path(override) if override else Path.home() / ".toolguard"


@dataclass(frozen=True)
class Approval:
    id: str
    session: str
    fingerprint: str
    tool: str
    summary: str
    status: str  # pending | approved | denied | consumed
    created: float
    decided: float | None
    decided_by: str | None


@dataclass(frozen=True)
class SessionInfo:
    session: str
    observations: int
    untrusted: int
    private: int
    first: float
    last: float


class Store:
    def __init__(self, path: str | Path | None = None) -> None:
        if path is None:
            home = default_home()
            home.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = home / "guard.db"
        self.path = str(path)
        memory = self.path == ":memory:"
        if not memory:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            created = not Path(self.path).exists()
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(
            self.path, timeout=30, isolation_level=None, check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row
        if not memory:
            self.conn.execute("PRAGMA journal_mode=WAL")
            if created and os.name != "nt":
                os.chmod(self.path, 0o600)
        self.conn.execute("PRAGMA busy_timeout=30000")
        with self._lock:
            self.conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialized write transaction (across threads and processes)."""
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            self.conn.execute("COMMIT")

    # ------------------------------------------------------------------ meta

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    # ------------------------------------------------------------------ observations

    def add_observation(
        self,
        *,
        session: str,
        ts: float,
        tool: str,
        kind: str,
        untrusted: bool,
        private: bool,
        trusted: bool,
        text: str,
        indicators: tuple[Indicator, ...],
        digest: str,
    ) -> Observation:
        payload = json.dumps([[i.kind, i.value] for i in indicators])
        with self.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO observations (session, ts, tool, kind, untrusted, private, trusted, "
                "text, indicators, digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (session, ts, tool, kind, untrusted, private, trusted, text, payload, digest),
            )
            row_id = int(cursor.lastrowid or 0)
        return Observation(
            row_id, session, ts, tool, kind, untrusted, private, trusted, text, indicators, digest
        )

    def observations(self, session: str, since: float | None = None) -> list[Observation]:
        query = "SELECT * FROM observations WHERE session = ?"
        params: list[object] = [session]
        if since is not None:
            query += " AND ts >= ?"
            params.append(since)
        with self._lock:
            rows = self.conn.execute(query + " ORDER BY id", params).fetchall()
        return [
            Observation(
                id=row["id"],
                session=row["session"],
                ts=row["ts"],
                tool=row["tool"],
                kind=row["kind"],
                untrusted=bool(row["untrusted"]),
                private=bool(row["private"]),
                trusted=bool(row["trusted"]),
                text=row["text"],
                indicators=tuple(Indicator(k, v) for k, v in json.loads(row["indicators"])),
                digest=row["digest"],
            )
            for row in rows
        ]

    def clear_session(self, session: str) -> int:
        with self.transaction() as conn:
            return conn.execute("DELETE FROM observations WHERE session = ?", (session,)).rowcount

    def sessions(self) -> list[SessionInfo]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT session, COUNT(*) AS n, SUM(untrusted) AS u, SUM(private) AS p, "
                "MIN(ts) AS first, MAX(ts) AS last FROM observations GROUP BY session ORDER BY last"
            ).fetchall()
        return [
            SessionInfo(r["session"], r["n"], r["u"] or 0, r["p"] or 0, r["first"], r["last"])
            for r in rows
        ]

    # ------------------------------------------------------------------ approvals

    @staticmethod
    def _approval(row: sqlite3.Row) -> Approval:
        return Approval(**{key: row[key] for key in row.keys()})  # noqa: SIM118

    def create_approval(
        self, *, session: str, fingerprint: str, tool: str, summary: str, now: float
    ) -> Approval:
        approval_id = secrets.token_hex(4)
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO approvals (id, session, fingerprint, tool, summary, status, created) "
                "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
                (approval_id, session, fingerprint, tool, summary, now),
            )
        return Approval(
            approval_id, session, fingerprint, tool, summary, "pending", now, None, None
        )

    def latest_approval(self, fingerprint: str, session: str) -> Approval | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM approvals WHERE fingerprint = ? AND session = ? "
                "ORDER BY created DESC, rowid DESC LIMIT 1",
                (fingerprint, session),
            ).fetchone()
        return self._approval(row) if row else None

    def get_approval(self, approval_id: str) -> Approval | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
        return self._approval(row) if row else None

    def list_approvals(self, status: str | None = None) -> list[Approval]:
        query, params = "SELECT * FROM approvals", ()
        if status:
            query, params = query + " WHERE status = ?", (status,)
        with self._lock:
            rows = self.conn.execute(query + " ORDER BY created", params).fetchall()
        return [self._approval(r) for r in rows]

    def decide_approval(self, approval_id: str, status: str, by: str, now: float) -> bool:
        """Move a *pending* approval to approved/denied. Returns False if not pending."""
        if status not in {"approved", "denied"}:
            raise ValueError(status)
        with self.transaction() as conn:
            changed = conn.execute(
                "UPDATE approvals SET status = ?, decided = ?, decided_by = ? "
                "WHERE id = ? AND status = 'pending'",
                (status, now, by, approval_id),
            ).rowcount
        return changed == 1

    def consume_approval(self, approval_id: str) -> bool:
        """Single use: approved -> consumed. Returns False if someone else consumed it."""
        with self.transaction() as conn:
            changed = conn.execute(
                "UPDATE approvals SET status = 'consumed' WHERE id = ? AND status = 'approved'",
                (approval_id,),
            ).rowcount
        return changed == 1

    # ------------------------------------------------------------------ audit rows

    def audit_head(self) -> tuple[int, str] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return (row["seq"], row["hash"]) if row else None

    def iter_audit(self, since: int = 0) -> Iterator[sqlite3.Row]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT seq, body, prev, hash FROM audit WHERE seq > ? ORDER BY seq", (since,)
            ).fetchall()
        yield from rows
