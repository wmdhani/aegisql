"""
AegisQL Guardrail Engine
Analyzes SQL Abstract Syntax Tree (AST) to enforce Read-Only principles,
prevent schema manipulation (DDL/DML), and inject execution limits.
"""
from typing import Tuple
import sqlglot
from sqlglot import exp

from app.core.i18n import translator


class SQLGuardrail:
    DEFAULT_MAX_LIMIT = 100

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
    def inspect_and_sanitize(cls, raw_sql: str, locale: str = "en") -> Tuple[bool, str, str]:
        """
        Validates and sanitizes SQL queries by parsing the Abstract Syntax Tree (AST).

        Args:
            raw_sql (str): The raw SQL string input from the user.
            locale (str): Client's preferred language code for localization.

        Returns:
            Tuple[bool, str, str]: (is_safe, sanitized_sql, reason_message)
        """
        cleaned_sql = raw_sql.strip()
        if not cleaned_sql:
            return False, "", translator.get(locale, "ERR_EMPTY_QUERY")

        try:
            parsed_statements = sqlglot.parse(cleaned_sql, read="mysql")
        except Exception as e:
            # We keep the raw exception for debugging, but prefix it
            return False, "", f"SQL Parser Error: {str(e)}"

        # 1. Prevent multi-statement queries (SQL injection chaining)
        if len(parsed_statements) > 1:
            return False, "", translator.get(locale, "ERR_MULTI_STATEMENT")

        statement = parsed_statements[0]

        # 2. Check for forbidden expressions (DDL / DML)
        for expr_type in cls.FORBIDDEN_EXPRESSIONS:
            if statement.find(expr_type):
                op_name = expr_type.__name__.upper()
                return False, "", translator.get(locale, "ERR_FORBIDDEN_OPERATION", operation=op_name)

        # 3. Ensure root statement is SELECT
        if not isinstance(statement, exp.Select):
            return False, "", translator.get(locale, "ERR_SELECT_ONLY")

        # 4. Limit Injection for DoS mitigation
        limit_node = statement.args.get("limit")
        if not limit_node:
            statement = statement.limit(cls.DEFAULT_MAX_LIMIT)
        else:
            try:
                current_limit = int(limit_node.expression.this)
                if current_limit > cls.DEFAULT_MAX_LIMIT:
                    statement.set("limit", exp.Limit(this=exp.Literal.number(cls.DEFAULT_MAX_LIMIT)))
            except (ValueError, AttributeError):
                statement.set("limit", exp.Limit(this=exp.Literal.number(cls.DEFAULT_MAX_LIMIT)))

        sanitized_sql = statement.sql(dialect="mysql")
        return True, sanitized_sql, translator.get(locale, "MSG_QUERY_SAFE")