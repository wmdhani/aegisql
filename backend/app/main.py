import time
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.core.guardrail import SQLGuardrail
from app.core.masking import sanitize_dataset
from app.services.db_service import TargetDatabaseService

app = FastAPI(
    title="AegisQL Security Engine",
    description="Zero-Trust Just-In-Time Data Access Bastion & Guardrail",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class QueryRequest(BaseModel):
    sql: str


class QueryExecutionResponse(BaseModel):
    is_safe: bool
    sanitized_sql: str
    row_count: int
    execution_time_ms: float
    data: List[Dict[str, Any]]


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "AegisQL Core API"}


@app.post("/api/v1/inspect")
async def inspect_query(payload: QueryRequest):
    is_safe, sanitized_sql, reason = SQLGuardrail.inspect_and_sanitize(payload.sql)
    return {
        "is_safe": is_safe,
        "sanitized_sql": sanitized_sql,
        "message": reason,
    }


@app.post("/api/v1/query/execute", response_model=QueryExecutionResponse)
async def execute_query(payload: QueryRequest):
    # 1. Pipeline Guardrail AST Inspection
    is_safe, sanitized_sql, reason = SQLGuardrail.inspect_and_sanitize(payload.sql)
    if not is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "GuardrailViolation", "reason": reason},
        )

    # 2. Pipeline Execution
    start_time = time.perf_counter()
    try:
        raw_rows = await TargetDatabaseService.execute_query(sanitized_sql)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "DatabaseExecutionError", "message": str(exc)},
        )
    execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

    # 3. Pipeline Dynamic PII & Financial Masking
    masked_data = sanitize_dataset(raw_rows)

    return QueryExecutionResponse(
        is_safe=True,
        sanitized_sql=sanitized_sql,
        row_count=len(masked_data),
        execution_time_ms=execution_time_ms,
        data=masked_data,
    )