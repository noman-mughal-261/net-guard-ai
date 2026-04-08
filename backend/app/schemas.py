from __future__ import annotations

from typing import Any

from pydantic import BaseModel, EmailStr, Field


class AnalyzeRequest(BaseModel):
    features: dict[str, Any] = Field(..., description="Flow feature names to values")
    source_ip: str | None = None


class BlockIpRequest(BaseModel):
    ip: str
    reason: str | None = None
    analyst: str | None = None


class AlertActionRequest(BaseModel):
    alert_id: str
    action: str  # monitor | ignore


class SignupRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
