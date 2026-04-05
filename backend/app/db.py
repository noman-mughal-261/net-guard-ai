from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from pymongo import MongoClient

from .config import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


_client: MongoClient | None = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(get_settings()["mongo_uri"])
    return _client


def get_db():
    return get_client()[get_settings()["mongo_db"]]


def insert_log(doc: dict[str, Any]) -> str:
    doc = {**doc, "created_at": utcnow()}
    res = get_db().logs.insert_one(doc)
    return str(res.inserted_id)


def insert_alert(doc: dict[str, Any]) -> str:
    doc = {**doc, "created_at": utcnow(), "analyst_status": "open"}
    res = get_db().alerts.insert_one(doc)
    return str(res.inserted_id)


def list_logs(limit: int = 200) -> list[dict]:
    cur = get_db().logs.find().sort("created_at", -1).limit(limit)
    return [_serialize(d) for d in cur]


def list_alerts(limit: int = 100) -> list[dict]:
    cur = get_db().alerts.find().sort("created_at", -1).limit(limit)
    return [_serialize(d) for d in cur]


def update_alert_status(alert_id: str, status: str) -> bool:
    try:
        oid = ObjectId(alert_id)
    except Exception:
        return False
    res = get_db().alerts.update_one(
        {"_id": oid},
        {"$set": {"analyst_status": status, "updated_at": utcnow()}},
    )
    return res.modified_count > 0 or res.matched_count > 0


def add_blocked_ip(
    ip: str,
    *,
    analyst: str | None,
    reason: str | None,
    firewall_ok: bool,
    firewall_message: str,
) -> str:
    doc = {
        "ip": ip,
        "blocked_at": utcnow(),
        "analyst": analyst,
        "reason": reason,
        "firewall_applied": firewall_ok,
        "firewall_message": firewall_message,
    }
    get_db().blocked_ips.update_one({"ip": ip}, {"$set": doc}, upsert=True)
    return ip


def list_blocked_ips() -> list[dict]:
    cur = get_db().blocked_ips.find().sort("blocked_at", -1)
    return [_serialize(d) for d in cur]


def is_ip_blocked(ip: str) -> bool:
    return get_db().blocked_ips.count_documents({"ip": ip}, limit=1) > 0


def insert_audit(entry: dict[str, Any]) -> None:
    entry = {**entry, "created_at": utcnow()}
    get_db().audit_logs.insert_one(entry)


def list_audit(limit: int = 100) -> list[dict]:
    cur = get_db().audit_logs.find().sort("created_at", -1).limit(limit)
    return [_serialize(d) for d in cur]


def _serialize(doc: dict) -> dict:
    out = dict(doc)
    if "_id" in out:
        out["_id"] = str(out["_id"])
    for k, v in list(out.items()):
        if isinstance(v, datetime):
            out[k] = v.isoformat()
    return out


def aggregate_threat_counts() -> list[dict]:
    pipeline = [
        {"$group": {"_id": "$label", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    return list(get_db().logs.aggregate(pipeline))
