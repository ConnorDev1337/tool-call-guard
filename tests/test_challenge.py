import sqlite3

import pytest

from toolguard.approvals import (
    CODE_ALPHABET,
    ChallengeSettings,
    answer_challenge,
    approval_key_from_env,
    code_matches,
    decision_is_authentic,
    decision_mac,
    hash_code,
    new_code,
    normalize_code,
)
from toolguard.store import Store

GOOD = "GOOD-GOOD-GOOD"


def test_codes_are_random_grouped_and_normalized():
    codes = {new_code() for _ in range(200)}
    assert len(codes) == 200  # 60 bits: collisions would mean a broken generator
    code = next(iter(codes))
    assert len(code) == 14 and code[4] == code[9] == "-"
    assert set(code.replace("-", "")) <= set(CODE_ALPHABET)
    assert len(new_code(10)) == 12  # 4-4-2
    assert normalize_code(" abcd-efgh ijkl ") == "ABCDEFGH1JK1"
    assert normalize_code("o0Il") == "0011"


def test_settings_validation():
    assert ChallengeSettings().algorithm == "sha256"
    assert ChallengeSettings(key=b"k").algorithm == "hmac-sha256"
    for bad in ({"length": 8}, {"length": 40}, {"max_attempts": 0}, {"code_ttl": 0}):
        with pytest.raises(ValueError):
            ChallengeSettings(**bad)


def test_hash_is_salted_bound_and_keyed():
    base = hash_code("ABCD-EFGH-JKMN", approval_id="a1", salt="s", key=None)
    assert base == hash_code("abcd efgh jkmn", approval_id="a1", salt="s", key=None)
    assert base != hash_code("ABCD-EFGH-JKMN", approval_id="a2", salt="s", key=None)
    assert base != hash_code("ABCD-EFGH-JKMN", approval_id="a1", salt="t", key=None)
    assert base != hash_code("ABCD-EFGH-JKMN", approval_id="a1", salt="s", key=b"k")
    assert "ABCD" not in base


def _pending(store, code, *, key=None, expires=1000.0):
    approval = store.create_approval(
        session="s", fingerprint="fp", tool="Bash", summary="why", now=10.0, expires=expires
    )
    digest = hash_code(code, approval_id=approval.id, salt="salt", key=key)
    with store.transaction() as conn:
        conn.execute(
            "UPDATE approvals SET code_hash = ?, code_salt = 'salt', code_alg = ? WHERE id = ?",
            (digest, "hmac-sha256" if key else "sha256", approval.id),
        )
    return store.get_approval(approval.id)


def test_code_matches_needs_the_right_key(store):
    approval = _pending(store, "CODE-CODE-CODE", key=b"k")
    assert code_matches(approval, "code-code-code", b"k") is True
    assert code_matches(approval, "CODE-CODE-COD0", b"k") is False
    assert code_matches(approval, "CODE-CODE-CODE", None) is None  # Cannot verify
    unkeyed = _pending(store, "CODE-CODE-CODE")
    assert code_matches(unkeyed, "CODE-CODE-CODE", b"k") is None
    bare = store.create_approval(session="s", fingerprint="f", tool="t", summary="", now=1.0)
    assert code_matches(bare, "anything", None) is False


def test_answer_challenge_approves_once(store):
    settings = ChallengeSettings(key=b"k")
    approval = _pending(store, "GOOD-GOOD-GOOD", key=b"k")
    result = answer_challenge(
        store, approval.id, "good good good", by="cli:alice", settings=settings, now=20.0
    )
    assert result.status == "approved"
    stored = store.get_approval(approval.id)
    assert stored.status == "approved" and stored.decided_by == "cli:alice"
    assert decision_is_authentic(stored, b"k") and not decision_is_authentic(stored, b"other")
    again = answer_challenge(
        store, approval.id, "GOOD-GOOD-GOOD", by="cli:alice", settings=settings, now=21.0
    )
    assert again.status == "not_pending"


def test_wrong_codes_lock_the_approval(store):
    settings = ChallengeSettings(max_attempts=3)
    approval = _pending(store, "GOOD-GOOD-GOOD")
    first = answer_challenge(store, approval.id, "BAD", by="x", settings=settings, now=20.0)
    assert first.status == "wrong" and first.attempts_left == 2
    second = answer_challenge(store, approval.id, "BAD", by="x", settings=settings, now=21.0)
    assert second.attempts_left == 1
    third = answer_challenge(store, approval.id, "BAD", by="x", settings=settings, now=22.0)
    assert third.status == "locked"
    assert store.get_approval(approval.id).status == "locked"
    # Locked for good: even the right code no longer works.
    late = answer_challenge(store, approval.id, GOOD, by="x", settings=settings, now=23)
    assert late.status == "not_pending"


def test_expired_unverifiable_and_codeless(store):
    settings = ChallengeSettings()
    expired = _pending(store, "GOOD-GOOD-GOOD", expires=15.0)
    result = answer_challenge(store, expired.id, GOOD, by="x", settings=settings, now=20)
    assert result.status == "expired" and store.get_approval(expired.id).status == "expired"
    keyed = _pending(store, "GOOD-GOOD-GOOD", key=b"k")
    result = answer_challenge(store, keyed.id, GOOD, by="x", settings=settings, now=20)
    assert result.status == "unverifiable"
    assert store.get_approval(keyed.id).attempts == 0  # Not counted as a guess
    legacy = store.create_approval(session="s", fingerprint="f", tool="t", summary="", now=1.0)
    result = answer_challenge(store, legacy.id, "x", by="x", settings=settings, now=2.0)
    assert result.status == "no_code"
    assert answer_challenge(store, "nope", "x", by="x", settings=settings, now=2).status == (
        "not_pending"
    )


def test_unauthenticated_decisions_are_detected(store):
    approval = _pending(store, "GOOD-GOOD-GOOD")
    assert decision_mac(approval, "approved", 1.0, "x", None) is None
    # Someone with write access to the database flips the status directly.
    store.decide_approval(approval.id, "approved", "cli:mallory", 30.0)
    forged = store.get_approval(approval.id)
    assert decision_is_authentic(forged, None)  # Without a key this cannot be told apart
    assert not decision_is_authentic(forged, b"k")


def test_store_closes_and_expires_approvals(store):
    first = store.create_approval(
        session="s", fingerprint="f", tool="t", summary="", now=1.0, expires=5.0
    )
    second = store.create_approval(
        session="s", fingerprint="g", tool="t", summary="", now=1.0, expires=50.0
    )
    assert [a.id for a in store.expire_approvals(10.0)] == [first.id]
    assert store.get_approval(first.id).status == "expired"
    assert store.close_approval(second.id, "undeliverable", 11.0)
    assert not store.close_approval(second.id, "locked", 12.0)
    store.set_approval_channel(second.id, "telegram")
    assert store.get_approval(second.id).channel == "telegram"
    with pytest.raises(ValueError):
        store.close_approval(second.id, "approved", 1.0)


def test_old_databases_are_migrated(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE approvals (id TEXT PRIMARY KEY, session TEXT NOT NULL, "
        "fingerprint TEXT NOT NULL, tool TEXT NOT NULL, summary TEXT NOT NULL, "
        "status TEXT NOT NULL, created REAL NOT NULL, decided REAL, decided_by TEXT)"
    )
    conn.execute(
        "INSERT INTO approvals VALUES ('old1', 's', 'f', 't', 'x', 'pending', 1, NULL, NULL)"
    )
    conn.commit()
    conn.close()
    with Store(path) as store:
        old = store.get_approval("old1")
        assert old.status == "pending" and old.code_hash is None and old.attempts == 0
    with Store(path) as again:  # Idempotent
        assert again.get_approval("old1").expires is None


def test_approval_key_from_env(monkeypatch):
    assert approval_key_from_env() is None
    monkeypatch.setenv("TOOLGUARD_AUDIT_KEY", "audit")
    assert approval_key_from_env() == b"audit"
    monkeypatch.setenv("TOOLGUARD_APPROVAL_KEY", "approval")
    assert approval_key_from_env() == b"approval"
    monkeypatch.setenv("OTHER_KEY", "other")
    assert approval_key_from_env("OTHER_KEY") == b"other"
