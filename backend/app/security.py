from __future__ import annotations

from fastapi import Header, HTTPException

from .config import get_settings

_TOKEN_PREFIX = ""
# _TOKEN_PREFIX = "demo-token-"


def parse_user_email_from_bearer(authorization: str | None) -> str | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    if not token.startswith(_TOKEN_PREFIX):
        return None
    email = token[len(_TOKEN_PREFIX) :].strip().lower()
    return email or None


def require_user_email(authorization: str | None = Header(None)) -> str:
    """Resolves the signed-in user from `Authorization: Bearer demo-token-<email>`."""
    email = parse_user_email_from_bearer(authorization)
    if not email:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated. Send Authorization: Bearer <token> from login.",
        )
    return email


def require_block_api_key(authorization: str | None = Header(None)) -> str:
    expected = get_settings()["block_api_key"]
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    if token != expected:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return token
