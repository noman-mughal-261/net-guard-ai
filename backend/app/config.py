from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


@lru_cache
def get_settings() -> dict:
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    default_artifacts = os.path.join(root, "ml", "artifacts")
    whitelist = os.getenv("WHITELIST_IPS", "127.0.0.1,::1")
    return {
        "mongo_uri": os.getenv("MONGODB_URI", "mongodb://localhost:27017"),
        "mongo_db": os.getenv("MONGODB_DB", "netguard_ai"),
        "artifact_dir": os.getenv("NETGUARD_ARTIFACT_DIR", default_artifacts),
        "model_filename": os.getenv("NETGUARD_MODEL_FILENAME", "model.pkl"),
        "alert_confidence_threshold": float(os.getenv("ALERT_CONFIDENCE_THRESHOLD", "0.90")),
        "block_api_key": os.getenv("BLOCK_API_KEY", "change-me-in-production"),
        "smtp_host": os.getenv("SMTP_HOST", ""),
        "smtp_port": int(os.getenv("SMTP_PORT", "587")),
        "smtp_user": os.getenv("SMTP_USER", ""),
        "smtp_password": os.getenv("SMTP_PASSWORD", ""),
        "smtp_from": os.getenv("SMTP_FROM", ""),
        "smtp_to": os.getenv("SMTP_TO", ""),
        "smtp_use_tls": os.getenv("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes"),
        "allow_block_private": os.getenv("ALLOW_BLOCK_PRIVATE", "false").lower()
        in ("1", "true", "yes"),
        "whitelist_ips": {ip.strip() for ip in whitelist.split(",") if ip.strip()},
        "cors_origins": [
            o.strip()
            for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(
                ","
            )
            if o.strip()
        ],
    }
