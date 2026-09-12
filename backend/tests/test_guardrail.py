"""
AegisQL Security Engine - Unit Test Suite
Tests AST parsing, DDL/DML interception, and automatic limit injection.
"""
import pytest
from app.core.guardrail import SQLGuardrail


def test_select_query_allowed_with_limit_injection():
    raw_query = "SELECT * FROM corporate_taxpayers"
    is_safe, sanitized_sql, _ = SQLGuardrail.inspect_and_sanitize(raw_query, locale="en")
    
    assert is_safe is True
    assert "LIMIT 100" in sanitized_sql.upper()


def test_destructive_ddl_blocked():
    destructive_query = "DROP TABLE corporate_taxpayers"
    is_safe, _, reason = SQLGuardrail.inspect_and_sanitize(destructive_query, locale="en")
    
    assert is_safe is False
    assert "DROP" in reason


def test_multi_statement_injection_blocked():
    chain_query = "SELECT * FROM corporate_taxpayers; DROP TABLE audit_transactions;"
    is_safe, _, reason = SQLGuardrail.inspect_and_sanitize(chain_query, locale="en")
    
    assert is_safe is False
    assert "Multi-statement" in reason


def test_limit_override_on_excessive_rows():
    excessive_limit_query = "SELECT * FROM corporate_taxpayers LIMIT 50000"
    is_safe, sanitized_sql, _ = SQLGuardrail.inspect_and_sanitize(excessive_limit_query, locale="en")
    
    assert is_safe is True
    assert "LIMIT 100" in sanitized_sql.upper()