import json
import sqlite3
from .models import Request, Response, Finding


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    options TEXT
);
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER,
    method TEXT, url TEXT, headers TEXT, body BLOB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS responses (
    id INTEGER PRIMARY KEY,
    request_id INTEGER,
    status INTEGER, headers TEXT, body BLOB, elapsed_ms INTEGER
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER, request_id INTEGER,
    module TEXT, name TEXT, severity TEXT,
    url TEXT, param TEXT, evidence TEXT,
    description TEXT, remediation TEXT, cvss REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


class Datastore:
    def __init__(self, path="umani.db"):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def new_scan(self, target, options=None):
        cur = self.conn.execute(
            "INSERT INTO scans (target, options) VALUES (?, ?)",
            (target, json.dumps(options or {})))
        self.conn.commit()
        return cur.lastrowid

    def save_request(self, req: Request) -> int:
        cur = self.conn.execute(
            "INSERT INTO requests (scan_id, method, url, headers, body) "
            "VALUES (?, ?, ?, ?, ?)",
            (req.scan_id, req.method, req.url,
             json.dumps(req.headers), req.body))
        self.conn.commit()
        return cur.lastrowid

    def save_response(self, res: Response) -> int:
        cur = self.conn.execute(
            "INSERT INTO responses (request_id, status, headers, body, elapsed_ms) "
            "VALUES (?, ?, ?, ?, ?)",
            (res.request_id, res.status, json.dumps(res.headers),
             res.body, res.elapsed_ms))
        self.conn.commit()
        return cur.lastrowid

    def save_finding(self, f: Finding) -> int:
        cur = self.conn.execute(
            "INSERT INTO findings (scan_id, request_id, module, name, severity, "
            "url, param, evidence, description, remediation, cvss) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (f.scan_id, f.request_id, f.module, f.name, f.severity,
             f.url, f.param, f.evidence, f.description, f.remediation, f.cvss))
        self.conn.commit()
        return cur.lastrowid

    def findings_for_scan(self, scan_id):
        cur = self.conn.execute(
            "SELECT module, name, severity, url, param, evidence, "
            "description, remediation FROM findings WHERE scan_id=?",
            (scan_id,))
        return cur.fetchall()
