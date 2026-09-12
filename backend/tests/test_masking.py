"""
AegisQL Dynamic Data Masking - Unit Test Suite
Tests heuristic PII detection and regex-based character obfuscation.
"""
from app.core.masking import mask_value, sanitize_result_row


def test_mask_value_formatting():
    # Test typical NIK/NPWP length
    sample_nik = "1271021203950001"
    masked = mask_value(sample_nik)
    
    assert masked.startswith("12")
    assert masked.endswith("01")
    assert "*" in masked
    assert len(masked) == len(sample_nik)


def test_sanitize_sensitive_row():
    mock_row = {
        "taxpayer_id": 1,
        "company_name": "PT Selaras Nusantara",
        "npwp": "01.345.678.9-123.000",
        "pic_nik": "1271021203950001",
        "pic_email": "finance@selaras.co.id"
    }
    sanitized = sanitize_result_row(mock_row)
    
    # Sensitive keys must be masked
    assert "*" in sanitized["npwp"]
    assert "*" in sanitized["pic_nik"]
    assert "*" in sanitized["pic_email"]
    
    # Non-sensitive keys remain untouched
    assert sanitized["taxpayer_id"] == 1
    assert sanitized["company_name"] == "PT Selaras Nusantara"