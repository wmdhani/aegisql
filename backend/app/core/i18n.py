"""
AegisQL Internationalization (i18n) Engine
Handles dynamic localization of error messages and system responses.
"""
import json
from pathlib import Path
from typing import Dict
from fastapi import Header

from app.core.config import settings


class I18nEngine:
    """Loads and retrieves translated strings from locale JSON files."""
    
    def __init__(self) -> None:
        self.locales: Dict[str, Dict[str, str]] = {}
        self._load_locales()

    def _load_locales(self) -> None:
        """Dynamically load all JSON files from the locales directory."""
        locales_dir = Path(__file__).parent.parent / "locales"
        for file_path in locales_dir.glob("*.json"):
            lang_code = file_path.stem  # e.g., 'en' or 'id'
            with open(file_path, "r", encoding="utf-8") as f:
                self.locales[lang_code] = json.load(f)

    def get(self, lang: str, key: str, **kwargs) -> str:
        """
        Retrieves a translated string. Falls back to English if key/lang is missing.
        """
        # Fallback to default if requested language is not supported
        if lang not in self.locales:
            lang = settings.DEFAULT_LOCALE
            
        text = self.locales[lang].get(key, key)
        
        # Format string if kwargs are provided (e.g., operation="DROP")
        if kwargs:
            text = text.format(**kwargs)
            
        return text


# Global instance of the translator
translator = I18nEngine()


def get_locale(accept_language: str = Header(default="en")) -> str:
    """
    FastAPI Dependency to extract preferred language from request headers.
    Parses headers like: 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'
    
    Returns:
        str: 'en' or 'id'
    """
    if not accept_language:
        return settings.DEFAULT_LOCALE
    
    # Extract the primary language code (e.g., 'id' from 'id-ID')
    primary_lang = accept_language.split(",")[0].split("-")[0].lower()
    
    if primary_lang in translator.locales:
        return primary_lang
    return settings.DEFAULT_LOCALE