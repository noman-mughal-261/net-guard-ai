from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


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
