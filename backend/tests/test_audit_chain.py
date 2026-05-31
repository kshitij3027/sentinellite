"""R9: hash-chain integrity is tamper-evident (pure-function level)."""

from __future__ import annotations

from sentinel.audit.chain import GENESIS_HASH, ChainRow, compute_hash, verify_rows


def _build_chain(n: int, tenant: str = "default") -> list[ChainRow]:
    rows: list[ChainRow] = []
    prev = GENESIS_HASH
    for i in range(1, n + 1):
        content = {"ts": f"2026-01-01T00:00:0{i}Z", "actor": "system", "event_type": "test", "data": {"i": i}}
        h = compute_hash(prev, i, tenant, content)
        rows.append(ChainRow(seq=i, tenant_id=tenant, content=content, prev_hash=prev, hash=h))
        prev = h
    return rows


def test_compute_hash_is_deterministic():
    c = {"ts": "t", "actor": "a", "event_type": "e", "data": {"x": 1}}
    assert compute_hash(GENESIS_HASH, 1, "default", c) == compute_hash(GENESIS_HASH, 1, "default", c)


def test_valid_chain_verifies():
    res = verify_rows(_build_chain(5))
    assert res["ok"] is True
    assert res["length"] == 5
    assert res["broken_index"] is None


def test_empty_chain_is_ok():
    assert verify_rows([])["ok"] is True


def test_tampering_content_breaks_chain():
    rows = _build_chain(5)
    rows[2].content["data"]["i"] = 999  # tamper row index 2
    res = verify_rows(rows)
    assert res["ok"] is False
    assert res["broken_index"] == 2
    assert res["reason"] == "hash mismatch"


def test_tampering_prev_hash_breaks_chain():
    rows = _build_chain(4)
    rows[1].prev_hash = "f" * 64
    res = verify_rows(rows)
    assert res["ok"] is False
    assert res["broken_index"] == 1
    assert res["reason"] == "prev_hash mismatch"


def test_deleting_a_row_breaks_chain():
    rows = _build_chain(5)
    del rows[2]  # removing a link orphans the next one's prev_hash
    res = verify_rows(rows)
    assert res["ok"] is False
    assert res["broken_index"] == 2
