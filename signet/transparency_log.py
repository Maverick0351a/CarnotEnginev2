import sqlite3, os, json, time, base64, hashlib
from typing import List, Dict

SCHEMA = """
CREATE TABLE IF NOT EXISTS leaves (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  leaf_hash TEXT NOT NULL,
  payload   BLOB NOT NULL,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sth (
  id INTEGER PRIMARY KEY CHECK (id=1),
  tree_size INTEGER NOT NULL,
  root_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  key_id TEXT NOT NULL,
  ts TEXT NOT NULL
);
INSERT OR IGNORE INTO sth(id, tree_size, root_hash, signature, key_id, ts)
  VALUES (1, 0, hex(zeroblob(32)), '', '', datetime('now'));
"""

class TransparencyLog:
  def __init__(self, path: str | None = None):
    if path is None:
      path = os.getenv('SIGNET_TL_PATH', '/tmp/signet_tl.db')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # allow usage across threads (FastAPI test client)
    self.db = sqlite3.connect(path, check_same_thread=False)
    self.db.executescript(SCHEMA)
    self.db.commit()

  def append(self, leaf_hash: bytes, payload: bytes) -> int:
    h = leaf_hash.hex()
    cur = self.db.cursor()
    cur.execute("INSERT INTO leaves(leaf_hash, payload, ts) VALUES (?, ?, ?)", (h, payload, time.time()))
    self.db.commit()
    return cur.lastrowid

  def leaves(self) -> List[Dict]:
    cur = self.db.cursor()
    rows = cur.execute("SELECT id, leaf_hash, payload, ts FROM leaves ORDER BY id ASC").fetchall()
    return [{"id": r[0], "leaf_hash": r[1], "payload": r[2], "ts": r[3]} for r in rows]

  def update_sth(self, tree_size: int, root_hash: bytes, signature: str, key_id: str):
    cur = self.db.cursor()
    cur.execute(
      "UPDATE sth SET tree_size=?, root_hash=?, signature=?, key_id=?, ts=datetime('now') WHERE id=1",
      (tree_size, root_hash.hex(), signature, key_id),
    )
    self.db.commit()

  def get_sth(self) -> Dict:
    cur = self.db.cursor()
    row = cur.execute("SELECT tree_size, root_hash, signature, key_id, ts FROM sth WHERE id=1").fetchone()
    return {
      "version": "1",
      "treeSize": row[0],
      "rootHash": row[1],
      "signature": row[2],
      "keyId": row[3],
      "timestamp": row[4],
    }
