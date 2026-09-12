"""
AegisQL Tamper-Proof Audit Logger
Mencatat aktivitas query dengan integritas kriptografis (Cryptographic Hash Chaining).
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


class AuditRecord:
    def __init__(
        self,
        session_id: str,
        username: str,
        raw_sql: str,
        sanitized_sql: str,
        rows_returned: int,
        execution_time_ms: float,
        previous_hash: str,
    ):
        self.timestamp: str = datetime.now(timezone.utc).isoformat()
        self.session_id: str = session_id
        self.username: str = username
        self.raw_sql: str = raw_sql
        self.sanitized_sql: str = sanitized_sql
        self.rows_returned: int = rows_returned
        self.execution_time_ms: float = execution_time_ms
        self.previous_hash: str = previous_hash
        self.current_hash: str = self._compute_hash()

    def _compute_hash(self) -> str:
        payload = {
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "username": self.username,
            "sanitized_sql": self.sanitized_sql,
            "rows_returned": self.rows_returned,
            "execution_time_ms": self.execution_time_ms,
            "previous_hash": self.previous_hash,
        }
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "username": self.username,
            "raw_sql": self.raw_sql,
            "sanitized_sql": self.sanitized_sql,
            "rows_returned": self.rows_returned,
            "execution_time_ms": self.execution_time_ms,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
        }


class AuditLedger:
    _genesis_hash: str = "0" * 64
    _chain: List[AuditRecord] = []

    @classmethod
    def record_event(
        cls,
        session_id: str,
        username: str,
        raw_sql: str,
        sanitized_sql: str,
        rows_returned: int,
        execution_time_ms: float,
    ) -> AuditRecord:
        prev_hash = cls._chain[-1].current_hash if cls._chain else cls._genesis_hash
        record = AuditRecord(
            session_id=session_id,
            username=username,
            raw_sql=raw_sql,
            sanitized_sql=sanitized_sql,
            rows_returned=rows_returned,
            execution_time_ms=execution_time_ms,
            previous_hash=prev_hash,
        )
        cls._chain.append(record)
        return record

    @classmethod
    def get_recent_logs(cls, limit: int = 50) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in reversed(cls._chain[-limit:])]

    @classmethod
    def verify_integrity(cls) -> Dict[str, Any]:
        """Memvalidasi integritas seluruh rantai audit log."""
        expected_prev = cls._genesis_hash
        for idx, record in enumerate(cls._chain):
            if record.previous_hash != expected_prev:
                return {
                    "is_valid": False,
                    "compromised_index": idx,
                    "reason": "Previous hash mismatch.",
                }
            recomputed = record._compute_hash()
            if record.current_hash != recomputed:
                return {
                    "is_valid": False,
                    "compromised_index": idx,
                    "reason": "Tampered record payload hash.",
                }
            expected_prev = record.current_hash

        return {
            "is_valid": True,
            "total_records": len(cls._chain),
            "status": "Cryptographic integrity intact.",
        }