import time
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Header, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.i18n import get_locale, translator
from app.core.guardrail import SQLGuardrail
from app.core.masking import sanitize_dataset
from app.core.session import SessionStore
from app.core.audit import AuditLedger
from app.services.db_service import TargetDatabaseService

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.API_VERSION,
    description="Zero-Trust Just-In-Time Data Access Bastion & Guardrail",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -- Pydantic Schemas --
class CreateSessionRequest(BaseModel):
    username: str = Field(..., example="dhani.analyst")
    justification: str = Field(..., example="Q3 Audit Reconciliation")
    duration_minutes: int = Field(default=settings.SESSION_TTL_MINUTES, ge=1, le=60)


class SessionResponse(BaseModel):
    session_id: str
    username: str
    justification: str
    is_active: bool
    remaining_seconds: int
    expires_at: str


class QueryRequest(BaseModel):
    sql: str


class QueryExecutionResponse(BaseModel):
    is_safe: bool
    sanitized_sql: str
    row_count: int
    execution_time_ms: float
    data: List[Dict[str, Any]]


# -- Endpoints --
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": settings.PROJECT_NAME, "version": settings.API_VERSION}


@app.post("/api/v1/sessions/request", response_model=SessionResponse)
async def request_access_session(payload: CreateSessionRequest):
    """Creates a temporary Just-In-Time (JIT) session."""
    session = SessionStore.create_session(
        username=payload.username,
        justification=payload.justification,
        duration_minutes=payload.duration_minutes,
    )
    return SessionResponse(
        session_id=session.session_id,
        username=session.username,
        justification=session.justification,
        is_active=session.is_active,
        remaining_seconds=session.remaining_seconds,
        expires_at=session.expires_at.isoformat(),
    )


@app.get("/api/v1/sessions/{session_id}", response_model=SessionResponse)
async def get_session_status(session_id: str, lang: str = Depends(get_locale)):
    """Checks the status and remaining TTL of an active session."""
    session = SessionStore.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ERR_SESSION_NOT_FOUND", "message": translator.get(lang, "ERR_SESSION_NOT_FOUND")}
        )
    return SessionResponse(
        session_id=session.session_id,
        username=session.username,
        justification=session.justification,
        is_active=session.is_active,
        remaining_seconds=session.remaining_seconds,
        expires_at=session.expires_at.isoformat(),
    )


@app.post("/api/v1/sessions/{session_id}/revoke")
async def revoke_session(session_id: str, lang: str = Depends(get_locale)):
    """Manually revokes a JIT session."""
    success = SessionStore.revoke_session(session_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ERR_SESSION_NOT_FOUND", "message": translator.get(lang, "ERR_SESSION_NOT_FOUND")}
        )
    return {"status": "revoked", "session_id": session_id}


@app.post("/api/v1/query/execute", response_model=QueryExecutionResponse)
async def execute_query(
    payload: QueryRequest,
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
    lang: str = Depends(get_locale)
):
    # 1. Zero-Trust Session Validation
    if not x_session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "ERR_HEADER_MISSING", "message": translator.get(lang, "ERR_HEADER_MISSING")}
        )

    session = SessionStore.get_session(x_session_id)
    if not session or not session.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "ERR_SESSION_EXPIRED", "message": translator.get(lang, "ERR_SESSION_EXPIRED")}
        )

    # 2. Pipeline Guardrail AST Inspection
    is_safe, sanitized_sql, reason = SQLGuardrail.inspect_and_sanitize(payload.sql, locale=lang)
    if not is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "ERR_GUARDRAIL_VIOLATION", "message": reason}
        )

    # 3. Pipeline Execution
    start_time = time.perf_counter()
    try:
        raw_rows = await TargetDatabaseService.execute_query(sanitized_sql)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "ERR_DB_EXECUTION", "message": translator.get(lang, "ERR_DB_EXECUTION", message=str(exc))}
        )
    execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

    # 4. Pipeline Dynamic PII Masking
    masked_data = sanitize_dataset(raw_rows)

    # 5. Pipeline Tamper-Proof Audit Logging
    AuditLedger.record_event(
        session_id=session.session_id,
        username=session.username,
        raw_sql=payload.sql,
        sanitized_sql=sanitized_sql,
        rows_returned=len(masked_data),
        execution_time_ms=execution_time_ms,
    )

    return QueryExecutionResponse(
        is_safe=True,
        sanitized_sql=sanitized_sql,
        row_count=len(masked_data),
        execution_time_ms=execution_time_ms,
        data=masked_data,
    )


@app.get("/api/v1/audit/logs")
async def get_audit_logs():
    """Retrieves the most recent audit logs for the dashboard trail."""
    return AuditLedger.get_recent_logs()


@app.get("/api/v1/audit/verify")
async def verify_audit_chain():
    """Validates the mathematical integrity of the cryptographic hash chain."""
    return AuditLedger.verify_integrity()