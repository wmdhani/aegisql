"""
AegisQL Guardrail Engine
Menganalisis SQL Abstract Syntax Tree (AST) untuk menegakkan prinsip Read-Only,
mencegah manipulasi skema (DDL/DML), dan menyuntikkan limit batas eksekusi.
"""

from typing import Tuple
import sqlglot
from sqlglot import exp


class SecurityViolationError(Exception):
    pass


class SQLGuardrail:
    DEFAULT_MAX_LIMIT = 100

    # Statement terlarang pada sesi read-only JIT
    FORBIDDEN_EXPRESSIONS = (
        exp.Drop,
        exp.Delete,
        exp.Update,
        exp.Insert,
        exp.Alter,
        exp.Create,
        exp.TruncateTable,
        exp.Grant,
        exp.Revoke,
    )

    @classmethod
    def inspect_and_sanitize(cls, raw_sql: str) -> Tuple[bool, str, str]:
        cleaned_sql = raw_sql.strip()
        if not cleaned_sql:
            return False, "", "Query kosong tidak diizinkan."

        try:
            parsed_statements = sqlglot.parse(cleaned_sql, read="mysql")
        except Exception as e:
            return False, "", f"Gagal parsing SQL syntax: {str(e)}"

        # 1. Cegah multi-statement query (mencegah teknik SQL injection chaining)
        if len(parsed_statements) > 1:
            return (
                False,
                "",
                "Pelanggaran Keamanan: Multi-statement query terdeteksi dan diblokir.",
            )

        statement = parsed_statements[0]

        # 2. Periksa ekspresi terlarang
        for expr_type in cls.FORBIDDEN_EXPRESSIONS:
            if statement.find(expr_type):
                return (
                    False,
                    "",
                    f"Pelanggaran Kebijakan: Operasi '{expr_type.__name__.upper()}' tidak diizinkan pada sesi JIT.",
                )

        # 3. Validasi root statement harus bertipe SELECT
        if not isinstance(statement, exp.Select):
            return False, "", "Akses Dibatasi: Hanya statement 'SELECT' yang diizinkan."

        # 4. Evaluasi klausa LIMIT untuk mitigasi Resource Exhaustion
        limit_node = statement.args.get("limit")
        if not limit_node:
            statement = statement.limit(cls.DEFAULT_MAX_LIMIT)
        else:
            try:
                current_limit = int(limit_node.expression.this)
                if current_limit > cls.DEFAULT_MAX_LIMIT:
                    statement.set(
                        "limit",
                        exp.Limit(this=exp.Literal.number(cls.DEFAULT_MAX_LIMIT)),
                    )
            except (ValueError, AttributeError):
                statement.set(
                    "limit", exp.Limit(this=exp.Literal.number(cls.DEFAULT_MAX_LIMIT))
                )

        sanitized_sql = statement.sql(dialect="mysql")
        return True, sanitized_sql, "Query lolos validasi keamanan."
