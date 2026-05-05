from __future__ import annotations

import pytest

from crovia_tlog.merkle import hash_leaf
from crovia_tlog.storage import DuplicateSealError, LogStorage


def test_append_and_read(tmp_path):
    s = LogStorage(tmp_path / "a.db")
    assert s.tree_size() == 0
    r = s.append(seal_id="cs_2026_AAAAAAAAAAAAAAAAAAAAAAAAAA", seal_bytes=b"hello")
    assert r.index == 0
    assert r.leaf_hash == hash_leaf(b"hello")
    assert s.tree_size() == 1

    got = s.get_leaf(0)
    assert got is not None and got.seal_id == r.seal_id

    by_id = s.get_leaf_by_seal_id("cs_2026_AAAAAAAAAAAAAAAAAAAAAAAAAA")
    assert by_id is not None and by_id.index == 0


def test_duplicate_seal_id_rejected(tmp_path):
    s = LogStorage(tmp_path / "b.db")
    s.append(seal_id="x", seal_bytes=b"a")
    with pytest.raises(DuplicateSealError):
        s.append(seal_id="x", seal_bytes=b"b")


def test_indices_are_contiguous_and_zero_based(tmp_path):
    s = LogStorage(tmp_path / "c.db")
    for i in range(5):
        r = s.append(seal_id=f"s{i}", seal_bytes=f"d{i}".encode())
        assert r.index == i
    hashes = s.all_leaf_hashes()
    assert len(hashes) == 5
    assert hashes[3] == hash_leaf(b"d3")


def test_all_leaf_hashes_up_to(tmp_path):
    s = LogStorage(tmp_path / "d.db")
    for i in range(10):
        s.append(seal_id=f"s{i}", seal_bytes=f"d{i}".encode())
    assert len(s.all_leaf_hashes(up_to=4)) == 4  # first 4 leaves, i.e. external indices 0..3
