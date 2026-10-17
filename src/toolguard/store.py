"""SQLite state shared by every process that guards the same agent.

One database holds the observations, approvals and audit chain. SQLite provides
cross-process locking, which matters because one agent may run several MCP
proxies and hook processes at once. The database contains copies of untrusted
and private content, so it is created with owner-only permissions where the OS
supports it.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
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
    digest TEXT NOT NULL,
    directed INTEGER NOT NULL DEFAULT 0
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
    decided_by TEXT,
    expires REAL,
    code_hash TEXT,
    code_salt TEXT,
    code_alg TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    channel TEXT,
    decision_mac TEXT
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

# Columns added to ``approvals`` after the first release, for databases created earlier.
_APPROVAL_COLUMNS = {
    "expires": "REAL",
    "code_hash": "TEXT",
    "code_salt": "TEXT",
    "code_alg": "TEXT",
    "attempts": "INTEGER NOT NULL DEFAULT 0",
    "channel": "TEXT",
    "decision_mac": "TEXT",
}

# Columns added to ``observations`` after the first release, for databases created earlier.
_OBSERVATION_COLUMNS = {
    "directed": "INTEGER NOT NULL DEFAULT 0",
}


def default_home() -> Path:
    """Return ``$TOOLGUARD_HOME`` if set, otherwise ``~/.toolguard``."""
    override = os.environ.get(ENV_HOME)
    return Path(override) if override else Path.home() / ".toolguard"


@dataclass(frozen=True)
class Approval:
    """A stored approval request, its one-time code challenge and its decision.

    Only a salted (and, with a key, keyed) hash of the code is stored, never the code.
    """

    id: str
    session: str
    fingerprint: str
    tool: str
    summary: str
    # "pending" | "approved" | "denied" | "consumed" | "expired" | "locked" | "undeliverable"
    status: str
    created: float
    decided: float | None
    decided_by: str | None
    expires: float | None = None
    code_hash: str | None = field(default=None, repr=False)
    code_salt: str | None = field(default=None, repr=False)
    code_alg: str | None = None
    attempts: int = 0
    channel: str | None = None  # Notifier that delivered the code
    decision_mac: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class SessionInfo:
    """Observation counts and time range of one session."""

    session: str
    observations: int
    untrusted: int
    private: int
    first: float
    last: float


class Store:
    """Thread-safe connection to the guard database.

    ``path=None`` uses ``guard.db`` in :func:`default_home`; ``":memory:"`` gives a
    private, non-persistent database.
    """

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
        self._migrate()

    def _migrate(self) -> None:
        """Add columns missing from databases created by earlier versions."""
        with self.transaction() as conn:
            for table, columns in (
                ("approvals", _APPROVAL_COLUMNS),
                ("observations", _OBSERVATION_COLUMNS),
            ):
                present = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
                for name, decl in columns.items():
                    if name not in present:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Safety net for short-lived CLI and hook processes; prefer an explicit close().
        with contextlib.suppress(Exception):
            self.conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a write transaction serialized across threads and processes."""
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
        directed: bool = False,
    ) -> Observation:
        payload = json.dumps([[i.kind, i.value] for i in indicators])
        with self.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO observations (session, ts, tool, kind, untrusted, private, trusted, "
                "text, indicators, digest, directed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session,
                    ts,
                    tool,
                    kind,
                    untrusted,
                    private,
                    trusted,
                    text,
                    payload,
                    digest,
                    directed,
                ),
            )
            row_id = int(cursor.lastrowid or 0)
        return Observation(
            row_id,
            session,
            ts,
            tool,
            kind,
            untrusted,
            private,
            trusted,
            text,
            indicators,
            digest,
            directed,
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
                directed=bool(row["directed"]),
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
                "MIN(ts) AS first, MAX(ts) AS last FROM observations "
                "GROUP BY session ORDER BY last"
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
        self,
        *,
        session: str,
        fingerprint: str,
        tool: str,
        summary: str,
        now: float,
        expires: float | None = None,
        code_hash: str | None = None,
        code_salt: str | None = None,
        code_alg: str | None = None,
        approval_id: str | None = None,
    ) -> Approval:
        approval_id = approval_id or secrets.token_hex(4)
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO approvals (id, session, fingerprint, tool, summary, status, created, "
                "expires, code_hash, code_salt, code_alg) "
                "VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)",
                (
                    approval_id,
                    session,
                    fingerprint,
                    tool,
                    summary,
                    now,
                    expires,
                    code_hash,
                    code_salt,
                    code_alg,
                ),
            )
        return Approval(
            approval_id,
            session,
            fingerprint,
            tool,
            summary,
            "pending",
            now,
            None,
            None,
            expires,
            code_hash,
            code_salt,
            code_alg,
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

    def decide_approval(
        self, approval_id: str, status: str, by: str, now: float, mac: str | None = None
    ) -> bool:
        """Record a human decision; return ``False`` if the approval is not pending.

        ``mac`` authenticates the decision when a key is configured. Raises ValueError
        unless ``status`` is ``"approved"`` or ``"denied"``.
        """
        if status not in {"approved", "denied"}:
            raise ValueError(status)
        with self.transaction() as conn:
            changed = conn.execute(
                "UPDATE approvals SET status = ?, decided = ?, decided_by = ?, decision_mac = ? "
                "WHERE id = ? AND status = 'pending'",
                (status, now, by, mac, approval_id),
            ).rowcount
        return changed == 1

    def close_approval(self, approval_id: str, status: str, now: float) -> bool:
        """Close a pending approval without a human decision; return whether it was pending.

        Raises ValueError unless ``status`` is ``"expired"``, ``"locked"`` or
        ``"undeliverable"``.
        """
        if status not in {"expired", "locked", "undeliverable"}:
            raise ValueError(status)
        with self.transaction() as conn:
            changed = conn.execute(
                "UPDATE approvals SET status = ?, decided = ? WHERE id = ? AND status = 'pending'",
                (status, now, approval_id),
            ).rowcount
        return changed == 1

    def set_approval_channel(self, approval_id: str, channel: str) -> None:
        """Record which notifier delivered the approval's code."""
        with self.transaction() as conn:
            conn.execute("UPDATE approvals SET channel = ? WHERE id = ?", (channel, approval_id))

    def expire_approvals(self, now: float) -> list[Approval]:
        """Mark pending approvals whose code has expired and return them."""
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status = 'pending' "
                "AND expires IS NOT NULL AND expires < ?",
                (now,),
            ).fetchall()
            conn.execute(
                "UPDATE approvals SET status = 'expired', decided = ? WHERE status = 'pending' "
                "AND expires IS NOT NULL AND expires < ?",
                (now, now),
            )
        return [self._approval(row) for row in rows]

    def answer_challenge(
        self,
        approval_id: str,
        *,
        check: Callable[[Approval], bool | None],
        now: float,
        max_attempts: int,
        by: str,
        sign: Callable[[Approval, float, str], str | None],
    ) -> tuple[str, Approval | None]:
        """Check a one-time code against a pending approval, atomically across processes.

        ``check`` returns whether the code matches, or ``None`` if it cannot be
        verified (e.g. the key is missing); ``sign`` returns the decision MAC. Returns
        ``(result, approval)``: ``result`` is ``"approved"``, ``"wrong"``, ``"locked"``,
        ``"expired"``, ``"not_pending"``, ``"no_code"`` or ``"unverifiable"``, and
        ``approval`` is the row as it was before the answer. Each wrong code counts as
        an attempt; at ``max_attempts`` the approval is locked.
        """
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
            approval = self._approval(row) if row else None
            if approval is None or approval.status != "pending":
                return "not_pending", approval
            if approval.expires is not None and now > approval.expires:
                conn.execute(
                    "UPDATE approvals SET status = 'expired', decided = ? WHERE id = ?",
                    (now, approval_id),
                )
                return "expired", approval
            if not approval.code_hash:
                return "no_code", approval
            verdict = check(approval)
            if verdict is None:
                return "unverifiable", approval
            if verdict:
                conn.execute(
                    "UPDATE approvals SET status = 'approved', decided = ?, decided_by = ?, "
                    "decision_mac = ? WHERE id = ?",
                    (now, by, sign(approval, now, by), approval_id),
                )
                return "approved", approval
            attempts = approval.attempts + 1
            status = "locked" if attempts >= max_attempts else "pending"
            conn.execute(
                "UPDATE approvals SET status = ?, attempts = ?, decided = ? WHERE id = ?",
                (status, attempts, now if status == "locked" else None, approval_id),
            )
            return ("locked" if status == "locked" else "wrong"), approval

    def consume_approval(self, approval_id: str) -> bool:
        """Mark an approval as used; return ``False`` if it is not (or no longer) approved."""
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
