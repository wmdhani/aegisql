from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from app.core.guardrail import SQLGuardrail

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


class QueryInspectRequest(BaseModel):
    sql: str


class QueryInspectResponse(BaseModel):
    is_safe: bool
    sanitized_sql: str
    message: str


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "AegisQL Core API"}


@app.post("/api/v1/inspect", response_model=QueryInspectResponse)
async def inspect_query(payload: QueryInspectRequest):
    is_safe, sanitized_sql, reason = SQLGuardrail.inspect_and_sanitize(payload.sql)
    return QueryInspectResponse(
        is_safe=is_safe,
        sanitized_sql=sanitized_sql,
        message=reason,
    )
