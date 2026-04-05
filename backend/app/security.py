from __future__ import annotations

from fastapi import Header, HTTPException

from .config import get_settings


def require_block_api_key(authorization: str | None = Header(None)) -> str:
    expected = get_settings()["block_api_key"]
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    if token != expected:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return token
