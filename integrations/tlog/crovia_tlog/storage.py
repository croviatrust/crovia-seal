"""
Append-only SQLite storage for Crovia Transparency Log leaves.

Schema (deliberately tiny, stable):

    CREATE TABLE leaves (
        idx         INTEGER PRIMARY KEY AUTOINCREMENT,
        leaf_hash   BLOB NOT NULL,        -- RFC 6962 leaf hash, 32 bytes
        leaf_data   BLOB NOT NULL,        -- raw submitted seal JSON bytes
        seal_id     TEXT NOT NULL,        -- convenient lookup key
        inserted_at TEXT NOT NULL         -- RFC 3339 UTC
    );
    CREATE UNIQUE INDEX idx_seal_id ON leaves(seal_id);

Append-only is enforced two ways:
    1. No UPDATE or DELETE statements exist in this module (auditable).
    2. A unique index on seal_id rejects duplicate submissions cheaply.

The whole leaf sequence is loaded into memory on demand; for a log serving
millions of entries this should be replaced with a segmented disk layout,
but for the v1 MVP SQLite with an in-memory leaf-hash vector is more than
sufficient and obviously correct.
"""
from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from crovia_tlog.merkle import hash_leaf


@dataclass(frozen=True)
class LeafRecord:
    index: int
    leaf_hash: bytes
    leaf_data: bytes
    seal_id: str
    inserted_at: str


class DuplicateSealError(ValueError):
    """Raised when a seal_id is submitted twice."""


class LogStorage:
    """Thread-safe SQLite-backed append-only leaf store."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS leaves (
        idx         INTEGER PRIMARY KEY AUTOINCREMENT,
        leaf_hash   BLOB NOT NULL,
        leaf_data   BLOB NOT NULL,
        seal_id     TEXT NOT NULL,
        inserted_at TEXT NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_seal_id ON leaves(seal_id);
    """

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = Path(db_path) if db_path != ":memory:" else db_path
        # A single connection guarded by a lock gives correctness without
        # juggling per-thread connections. The log is write-rare,
        # read-frequent so this is fine.
        self._conn = sqlite3.connect(
            self._db_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,
            isolation_level=None,  # autocommit; we open our own transactions
        )
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.executescript(self._SCHEMA)
        self._lock = threading.Lock()

    # -----------------------------------------------------------------

    def append(self, *, seal_id: str, seal_bytes: bytes) -> LeafRecord:
        """Append a seal to the log. Raises DuplicateSealError if seal_id exists."""
        leaf_hash = hash_leaf(seal_bytes)
        ts = _now_rfc3339()
        with self._lock:
            try:
                cur = self._conn.execute(
                    "INSERT INTO leaves (leaf_hash, leaf_data, seal_id, inserted_at) VALUES (?, ?, ?, ?)",
                    (leaf_hash, seal_bytes, seal_id, ts),
                )
            except sqlite3.IntegrityError as e:
                raise DuplicateSealError(f"seal_id already in log: {seal_id}") from e
            idx = cur.lastrowid
        # SQLite AUTOINCREMENT starts at 1. The log uses 0-based indices for
        # RFC 6962 compliance, so we subtract 1 here and forever treat
        # `idx` as `sqlite_rowid - 1`.
        assert idx is not None
        return LeafRecord(
            index=idx - 1,
            leaf_hash=leaf_hash,
            leaf_data=seal_bytes,
            seal_id=seal_id,
            inserted_at=ts,
        )

    def tree_size(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM leaves").fetchone()
        return int(row[0])

    def get_leaf(self, index: int) -> Optional[LeafRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT idx, leaf_hash, leaf_data, seal_id, inserted_at FROM leaves WHERE idx = ?",
                (index + 1,),
            ).fetchone()
        if row is None:
            return None
        return LeafRecord(
            index=row[0] - 1,
            leaf_hash=row[1],
            leaf_data=row[2],
            seal_id=row[3],
            inserted_at=row[4],
        )

    def get_leaf_by_seal_id(self, seal_id: str) -> Optional[LeafRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT idx, leaf_hash, leaf_data, seal_id, inserted_at FROM leaves WHERE seal_id = ?",
                (seal_id,),
            ).fetchone()
        if row is None:
            return None
        return LeafRecord(
            index=row[0] - 1,
            leaf_hash=row[1],
            leaf_data=row[2],
            seal_id=row[3],
            inserted_at=row[4],
        )

    def all_leaf_hashes(self, up_to: Optional[int] = None) -> List[bytes]:
        """Return the leaf_hashes[0 .. up_to-1] list used by merkle routines."""
        with self._lock:
            if up_to is None:
                rows = self._conn.execute(
                    "SELECT leaf_hash FROM leaves ORDER BY idx"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT leaf_hash FROM leaves WHERE idx <= ? ORDER BY idx",
                    (up_to,),
                ).fetchall()
        return [r[0] for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _now_rfc3339() -> str:
    now = datetime.now(tz=timezone.utc)
    ms = now.microsecond // 1000
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"
