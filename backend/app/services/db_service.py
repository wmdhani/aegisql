"""
AegisQL Database Service
Manages asynchronous connections to the isolated target MySQL database.
"""
import aiomysql
from typing import List, Dict, Any

from app.core.config import settings


class TargetDatabaseService:
    @classmethod
    async def get_connection(cls):
        """Creates an async connection to the target database."""
        return await aiomysql.connect(
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            user=settings.DB_USER,
            password=settings.DB_ROOT_PASSWORD,
            db=settings.DB_NAME,
            autocommit=True,
            charset="utf8mb4",
        )

    @classmethod
    async def execute_query(cls, sanitized_sql: str) -> List[Dict[str, Any]]:
        """
        Executes a sanitized SQL query and returns the rows as a list of dicts.
        """
        conn = await cls.get_connection()
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute(sanitized_sql)
                results = await cursor.fetchall()
                return list(results)
        finally:
            conn.close()