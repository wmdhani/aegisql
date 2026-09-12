"""
AegisQL Database Service
Mengelola koneksi asinkron ke target MySQL database yang terisolasi.
"""
import os
import aiomysql
from typing import List, Dict, Any

DB_HOST = os.getenv("DB_HOST", "target-db")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = "root"
DB_PASSWORD = os.getenv("DB_ROOT_PASSWORD", "super_secret_root_password")
DB_NAME = os.getenv("DB_NAME", "dummy_finance_db")


class TargetDatabaseService:
    @classmethod
    async def get_connection(cls):
        return await aiomysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            db=DB_NAME,
            autocommit=True,
            charset="utf8mb4",
        )

    @classmethod
    async def execute_query(cls, sanitized_sql: str) -> List[Dict[str, Any]]:
        """
        Mengeksekusi sanitized SQL query dan mengembalikan hasil dalam bentuk list of dicts.
        """
        conn = await cls.get_connection()
        try:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute(sanitized_sql)
                results = await cursor.fetchall()
                return list(results)
        finally:
            conn.close()