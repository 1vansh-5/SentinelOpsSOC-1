
import os
import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = os.getenv("SENTINELOPS_DB", "sentinelops.db")


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if os.path.dirname(DB_PATH):
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    with closing(connect()) as conn, conn:

        # Alerts table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                source_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                target TEXT NOT NULL,
                details TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new'
            )
        """)

        
        # Incidents table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                assessment TEXT NOT NULL,
                confidence TEXT NOT NULL,
                evidence TEXT NOT NULL,
                response_action TEXT NOT NULL,
                response_status TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            )
        """)

        # Phase 3C: Approval requests
        conn.execute("""
            CREATE TABLE IF NOT EXISTS response_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                source_ip TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                requested_at TEXT NOT NULL DEFAULT (datetime('now')),
                decided_at TEXT,
                decided_by TEXT,
                FOREIGN KEY(incident_id) REFERENCES incidents(id)
            )
        """)

        # Phase 3C: Persistent simulated blocks
        conn.execute("""
            CREATE TABLE IF NOT EXISTS simulated_blocks (
                source_ip TEXT PRIMARY KEY,
                response_request_id INTEGER NOT NULL,
                blocked_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(response_request_id)
                    REFERENCES response_requests(id)
            )
        """)

        # Phase 3C: Audit history
        conn.execute("""
            CREATE TABLE IF NOT EXISTS response_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                response_request_id INTEGER,
                incident_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
