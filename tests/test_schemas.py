"""
Unit tests for Pydantic schemas.
These tests run entirely in memory and do not require a database or Redis.
"""
import pytest
from pydantic import ValidationError

from app.schemas import OTPEvaluateRequest, FailedLoginReport, OTPAction


class TestOTPEvaluateRequest:
    """Tests for the OTP evaluation request schema."""

    def test_valid_request(self):
        """Ensure a perfectly valid request passes validation."""
        req = OTPEvaluateRequest(
            user_id="user_123",
            phone_number="+15551234567",
            ip_address="198.51.100.1"
        )
        assert req.user_id == "user_123"
        assert req.phone_number == "+15551234567"
        assert req.ip_address == "198.51.100.1"

    def test_invalid_phone_number_missing_plus(self):
        """Ensure phone numbers without a '+' are rejected."""
        with pytest.raises(ValidationError):
            OTPEvaluateRequest(
                user_id="user_123",
                phone_number="15551234567",  # Missing '+'
                ip_address="198.51.100.1"
            )

    def test_invalid_phone_number_too_short(self):
        """Ensure phone numbers that are too short are rejected."""
        with pytest.raises(ValidationError):
            OTPEvaluateRequest(
                user_id="user_123",
                phone_number="+1555",  # Too short
                ip_address="198.51.100.1"
            )

    def test_invalid_ip_address(self):
        """Ensure invalid IP addresses are rejected."""
        with pytest.raises(ValidationError):
            OTPEvaluateRequest(
                user_id="user_123",
                phone_number="+15551234567",
                ip_address="999.999.999.999"  # Invalid IP
            )

    def test_invalid_ip_address_string(self):
        """Ensure random strings are rejected as IP addresses."""
        with pytest.raises(ValidationError):
            OTPEvaluateRequest(
                user_id="user_123",
                phone_number="+15551234567",
                ip_address="not-an-ip-address"
            )


class TestFailedLoginReport:
    """Tests for the failed login reporting schema."""

    def test_valid_report(self):
        """Ensure a valid failed login report passes."""
        report = FailedLoginReport(
            user_id="user_456",
            ip_address="203.0.113.45"
        )
        assert report.user_id == "user_456"
        assert report.ip_address == "203.0.113.45"
        assert report.metadata is None  # Optional field defaults to None

    def test_report_with_metadata(self):
        """Ensure metadata is correctly parsed."""
        report = FailedLoginReport(
            user_id="user_456",
            ip_address="203.0.113.45",
            metadata={"user_agent": "Mozilla/5.0", "reason": "wrong_password"}
        )
        assert report.metadata["user_agent"] == "Mozilla/5.0"


class TestOTPAction:
    """Tests for the OTP Action Enum."""

    def test_enum_values(self):
        """Ensure the OTPAction enum has the correct string values."""
        assert OTPAction.ALLOW.value == "ALLOW"
        assert OTPAction.BLOCK.value == "BLOCK"
        assert OTPAction.CHALLENGE.value == "CHALLENGE"

    def test_enum_is_string(self):
        """Ensure the enum inherits from str for easy JSON serialization."""
        assert isinstance(OTPAction.ALLOW, str)