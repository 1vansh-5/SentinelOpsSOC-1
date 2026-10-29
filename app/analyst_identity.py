"""Local analyst identity and role registry for SentinelOps SOC.

Simulation-first authorization foundation. Tokens are high-entropy bearer secrets;
only SHA-256 digests are persisted. Do not expose this registry directly to clients.
"""

import hashlib
import hmac
import re
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

ROLES = frozenset({"viewer", "analyst", "admin"})
PERMISSIONS = {
    "view": frozenset(ROLES),
    "decide": frozenset({"analyst", "admin"}),
    "manage_analysts": frozenset({"admin"}),
}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AnalystIdentityStore:
    """Persistent identity records with revocation and role-based permissions."""

    def __init__(self, database_path: str):
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def _connect(self):
        conn = sqlite3.connect(self.database_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        with closing(self._connect()) as conn, conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS analysts (
                analyst_id TEXT PRIMARY KEY,
                role TEXT NOT NULL CHECK(role IN ('viewer','analyst','admin')),
                token_digest TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )""")

    def create_analyst(self, analyst_id: str, role: str, *, token: str | None = None) -> dict:
        """Provision a new analyst. Return the bearer token exactly once."""
        if not isinstance(analyst_id, str) or not _ID.fullmatch(analyst_id):
            raise ValueError("Invalid analyst ID")
        if role not in ROLES:
            raise ValueError("Invalid analyst role")
        if token is None:
            token = secrets.token_urlsafe(48)
        if not isinstance(token, str) or len(token) < 32 or len(token) > 512:
            raise ValueError("Analyst token must be at least 32 characters")
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO analysts (analyst_id, role, token_digest) VALUES (?, ?, ?)",
                (analyst_id, role, _digest(token)),
            )
        return {"analyst_id": analyst_id, "role": role, "token": token}

    def authenticate(self, analyst_id: str, token: str) -> dict | None:
        """Return only public identity details; never return stored token material."""
        if (not isinstance(analyst_id, str) or not isinstance(token, str)
                or len(token) < 32 or len(token) > 512):
            return None
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT analyst_id, role, token_digest, enabled FROM analysts WHERE analyst_id = ?",
                (analyst_id,),
            ).fetchone()
        if row is None or row["enabled"] != 1:
            return None
        if not hmac.compare_digest(row["token_digest"], _digest(token)):
            return None
        return {"analyst_id": row["analyst_id"], "role": row["role"]}

    def authorize(self, analyst_id: str, token: str, permission: str) -> dict | None:
        if permission not in PERMISSIONS:
            return None
        identity = self.authenticate(analyst_id, token)
        if identity is None or identity["role"] not in PERMISSIONS[permission]:
            return None
        return identity

    def disable_analyst(self, analyst_id: str) -> bool:
        with closing(self._connect()) as conn, conn:
            result = conn.execute(
                "UPDATE analysts SET enabled = 0 WHERE analyst_id = ? AND enabled = 1",
                (analyst_id,),
            )
            return result.rowcount == 1

    def change_role(self, analyst_id: str, role: str) -> bool:
        if role not in ROLES:
            raise ValueError("Invalid analyst role")
        with closing(self._connect()) as conn, conn:
            result = conn.execute(
                "UPDATE analysts SET role = ? WHERE analyst_id = ? AND enabled = 1",
                (role, analyst_id),
            )
            return result.rowcount == 1

    def rotate_token(self, analyst_id: str) -> str | None:
        """Invalidate old token immediately; return the replacement once."""
        new_token = secrets.token_urlsafe(48)
        with closing(self._connect()) as conn, conn:
            result = conn.execute(
                "UPDATE analysts SET token_digest = ? WHERE analyst_id = ? AND enabled = 1",
                (_digest(new_token), analyst_id),
            )
            return new_token if result.rowcount == 1 else None
