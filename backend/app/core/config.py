"""
AegisQL Configuration Manager
Centralized environment variables validation using Pydantic Settings.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    # App Meta
    PROJECT_NAME: str = "AegisQL Security Engine"
    API_VERSION: str = "1.0.0"
    DEFAULT_LOCALE: str = "en"

    # Security
    SECRET_KEY: str = "default_unsafe_secret"
    SESSION_TTL_MINUTES: int = 15

    # Database Target
    DB_HOST: str = "target-db"
    DB_PORT: int = 3306
    DB_USER: str = "root"
    DB_ROOT_PASSWORD: str
    DB_NAME: str = "dummy_finance_db"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"  # Ignore env variables not defined here
    )


# Instantiate settings statically so it can be imported across modules
settings = Settings()