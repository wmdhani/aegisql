"""
AegisQL Just-In-Time (JIT) Session Manager
Mengelola sesi akses sementara berbasis Time-To-Live (TTL).
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
import uuid


class AccessSession:
    def __init__(self, username: str, justification: str, duration_minutes: int = 15):
        self.session_id: str = str(uuid.uuid4())
        self.username: str = username
        self.justification: str = justification
        self.created_at: datetime = datetime.now(timezone.utc)
        self.expires_at: datetime = self.created_at + timedelta(minutes=duration_minutes)
        self.is_revoked: bool = False

    @property
    def is_active(self) -> bool:
        if self.is_revoked:
            return False
        return datetime.now(timezone.utc) < self.expires_at

    @property
    def remaining_seconds(self) -> int:
        if not self.is_active:
            return 0
        diff = self.expires_at - datetime.now(timezone.utc)
        return max(0, int(diff.total_seconds()))


class SessionStore:
    _sessions: Dict[str, AccessSession] = {}

    @classmethod
    def create_session(cls, username: str, justification: str, duration_minutes: int = 15) -> AccessSession:
        session = AccessSession(
            username=username,
            justification=justification,
            duration_minutes=duration_minutes,
        )
        cls._sessions[session.session_id] = session
        return session

    @classmethod
    def get_session(cls, session_id: str) -> Optional[AccessSession]:
        return cls._sessions.get(session_id)

    @classmethod
    def revoke_session(cls, session_id: str) -> bool:
        session = cls._sessions.get(session_id)
        if session:
            session.is_revoked = True
            return True
        return False