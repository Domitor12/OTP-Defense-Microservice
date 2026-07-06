"""
Request / response schemas with strict validation.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator
import re


# ── Enums ──────────────────────────────────────────────────────────

class OTPAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    CHALLENGE = "CHALLENGE"


# ── Requests ───────────────────────────────────────────────────────

class OTPEvaluateRequest(BaseModel):
    """Payload sent by the login system before dispatching an OTP."""

    user_id: str = Field(
        ..., min_length=1, max_length=255,
        description="Internal user identifier",
    )
    phone_number: str = Field(
        ..., min_length=7, max_length=20,
        description="E.164 formatted phone number, e.g. +15551234567",
    )
    ip_address: str = Field(
        ..., min_length=7, max_length=45,
        description="Client IPv4 or IPv6 address",
    )
    device_fingerprint: Optional[str] = Field(
        default=None, max_length=512,
        description="Optional browser/device fingerprint hash",
    )

    @field_validator("phone_number")
    @classmethod
    def validate_e164(cls, v: str) -> str:
        if not re.match(r"^\+[1-9]\d{6,14}$", v):
            raise ValueError(
                "phone_number must be in E.164 format (e.g. +15551234567)"
            )
        return v

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v


class FailedLoginReport(BaseModel):
    """Payload to report a failed login attempt."""

    user_id: str = Field(..., min_length=1, max_length=255)
    ip_address: str = Field(..., min_length=7, max_length=45)
    metadata: Optional[dict] = Field(default=None)


# ── Responses ──────────────────────────────────────────────────────

class OTPEvaluateResponse(BaseModel):
    """Returned to the calling login system."""

    action: OTPAction
    reason: str
    request_id: str = Field(description="Traceable unique ID for this evaluation")
    evaluated_at: datetime
    details: dict = Field(
        default_factory=dict,
        description="Additional context (e.g., counts, flags) for logging",
    )


class HealthResponse(BaseModel):
    status: str
    postgres: str
    redis: str
    version: str = "1.0.0"