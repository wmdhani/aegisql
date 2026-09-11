"""
AegisQL Dynamic Data Masker
Menyaring dan menyamarkan kolom sensitif (PII & Financial Identifiers).
"""

from typing import Any, Dict, List
import re

SENSITIVE_PATTERNS = [
    re.compile(r"nik", re.IGNORECASE),
    re.compile(r"npwp", re.IGNORECASE),
    re.compile(r"rekening|bank_acc", re.IGNORECASE),
    re.compile(r"phone|telepon|hp", re.IGNORECASE),
    re.compile(r"email", re.IGNORECASE),
]


def mask_value(val: Any) -> str:
    if val is None:
        return ""
    str_val = str(val).strip()
    length = len(str_val)

    if length <= 4:
        return "****"

    visible_prefix = 2
    visible_suffix = 2

    if length <= 8:
        visible_prefix = 1
        visible_suffix = 1

    mask_len = length - (visible_prefix + visible_suffix)
    return str_val[:visible_prefix] + ("*" * mask_len) + str_val[-visible_suffix:]


def sanitize_result_row(row: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = {}
    for col_name, value in row.items():
        is_sensitive = any(pattern.search(col_name) for pattern in SENSITIVE_PATTERNS)
        if is_sensitive and value is not None:
            sanitized[col_name] = mask_value(value)
        else:
            sanitized[col_name] = value
    return sanitized


def sanitize_dataset(dataset: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [sanitize_result_row(row) for row in dataset]
