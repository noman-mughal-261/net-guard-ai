from __future__ import annotations

import re
from pathlib import Path

from fastapi import HTTPException, UploadFile

from .config import get_settings
from .db import update_user_profile

_ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
_EXT_BY_TYPE = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/gif": ".gif",
}


def _avatar_filename(email: str, ext: str) -> str:
    safe = re.sub(r"[^a-z0-9]+", "_", email.lower().strip())
    return f"{safe}{ext}"


def save_avatar(email: str, upload: UploadFile) -> str:
    content_type = (upload.content_type or "").lower()
    if content_type not in _ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail="Avatar must be JPEG, PNG, WebP, or GIF")

    data = upload.file.read()
    max_bytes = get_settings()["max_avatar_bytes"]
    if len(data) > max_bytes:
        raise HTTPException(status_code=400, detail=f"Avatar must be under {max_bytes // (1024 * 1024)} MB")

    ext = _EXT_BY_TYPE[content_type]
    upload_dir = Path(get_settings()["upload_dir"]) / "avatars"
    upload_dir.mkdir(parents=True, exist_ok=True)

    filename = _avatar_filename(email, ext)
    path = upload_dir / filename
    path.write_bytes(data)

    avatar_url = f"/api/uploads/avatars/{filename}"
    updated = update_user_profile(email, avatar_url=avatar_url)
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    return avatar_url
