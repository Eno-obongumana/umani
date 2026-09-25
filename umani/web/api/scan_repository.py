"""Repository layer — all database access goes through here.

Nothing outside this file talks to SQLite directly. If you switch to
Postgres later, only this file changes.
"""
from typing import Optional
from ...core.datastore import Datastore


class ScanRepository:
    def __init__(self, db_path: str = "umani.db"):
        self.db_path = db_path

    # ─── Scans ────────────────────────────────────

    def create_scan(self, target: str, options: dict) -> int:
        store = Datastore(self.db_path)
        return store.new_scan(target, options)

    def list_scans(self, limit: int = 100) -> list[dict]:
        store = Datastore(self.db_path)
        cur = store.conn.execute(
            "SELECT id, target, started_at FROM scans "
            "ORDER BY id DESC LIMIT ?", (limit,))
        return [
            {"id": row[0], "target": row[1], "started_at": row[2]}
            for row in cur.fetchall()
        ]

    def get_scan(self, scan_id: int) -> Optional[dict]:
        store = Datastore(self.db_path)
        cur = store.conn.execute(
            "SELECT id, target, started_at FROM scans WHERE id = ?",
            (scan_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {"id": row[0], "target": row[1], "started_at": row[2]}

    def count_findings(self, scan_id: int) -> int:
        store = Datastore(self.db_path)
        cur = store.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,))
        return cur.fetchone()[0]

    # ─── Findings ─────────────────────────────────

    def get_findings(self, scan_id: int) -> list[dict]:
        store = Datastore(self.db_path)
        return store.list_findings(scan_id)

    def get_finding(self, finding_id: int) -> Optional[dict]:
        store = Datastore(self.db_path)
        return store.get_finding(finding_id)
