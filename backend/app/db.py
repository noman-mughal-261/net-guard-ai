from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from pymongo import MongoClient

from .config import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _norm_email(user_email: str) -> str:
    return user_email.lower().strip()


def _uf(user_email: str) -> dict[str, Any]:
    return {"user_email": _norm_email(user_email)}


_client: MongoClient | None = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(get_settings()["mongo_uri"])
    return _client


def get_db():
    return get_client()[get_settings()["mongo_db"]]


def insert_log(doc: dict[str, Any], user_email: str) -> str:
    doc = {**doc, **_uf(user_email), "created_at": utcnow()}
    res = get_db().logs.insert_one(doc)
    return str(res.inserted_id)


def insert_alert(doc: dict[str, Any], user_email: str) -> str:
    doc = {
        **doc,
        **_uf(user_email),
        "created_at": utcnow(),
        "analyst_status": "open",
    }
    res = get_db().alerts.insert_one(doc)
    return str(res.inserted_id)


def list_logs(user_email: str, limit: int = 200) -> list[dict]:
    cur = get_db().logs.find(_uf(user_email)).sort("created_at", -1).limit(limit)
    return [_serialize(d) for d in cur]


def list_alerts(user_email: str, limit: int = 100) -> list[dict]:
    cur = get_db().alerts.find(_uf(user_email)).sort("created_at", -1).limit(limit)
    return [_serialize(d) for d in cur]


def update_alert_status(alert_id: str, status: str, user_email: str) -> bool:
    try:
        oid = ObjectId(alert_id)
    except Exception:
        return False
    res = get_db().alerts.update_one(
        {"_id": oid, **_uf(user_email)},
        {"$set": {"analyst_status": status, "updated_at": utcnow()}},
    )
    return res.modified_count > 0 or res.matched_count > 0


def add_blocked_ip(
    ip: str,
    user_email: str,
    *,
    analyst: str | None,
    reason: str | None,
    firewall_ok: bool,
    firewall_message: str,
) -> str:
    doc = {
        "ip": ip,
        **_uf(user_email),
        "blocked_at": utcnow(),
        "analyst": analyst,
        "reason": reason,
        "firewall_applied": firewall_ok,
        "firewall_message": firewall_message,
    }
    get_db().blocked_ips.update_one({"ip": ip, **_uf(user_email)}, {"$set": doc}, upsert=True)
    return ip


def list_blocked_ips(user_email: str) -> list[dict]:
    cur = get_db().blocked_ips.find(_uf(user_email)).sort("blocked_at", -1)
    return [_serialize(d) for d in cur]


def is_ip_blocked(ip: str, user_email: str) -> bool:
    return get_db().blocked_ips.count_documents({"ip": ip, **_uf(user_email)}, limit=1) > 0


def insert_audit(entry: dict[str, Any], user_email: str | None = None) -> None:
    doc = {**entry, "created_at": utcnow()}
    if user_email is not None:
        doc = {**doc, **_uf(user_email)}
    get_db().audit_logs.insert_one(doc)


def list_audit(user_email: str, limit: int = 100) -> list[dict]:
    cur = get_db().audit_logs.find(_uf(user_email)).sort("created_at", -1).limit(limit)
    return [_serialize(d) for d in cur]


def _serialize(doc: dict) -> dict:
    out = dict(doc)
    if "_id" in out:
        out["_id"] = str(out["_id"])
    for k, v in list(out.items()):
        if isinstance(v, datetime):
            out[k] = v.isoformat()
    return out


def aggregate_threat_counts(user_email: str) -> list[dict]:
    pipeline = [
        {"$match": _uf(user_email)},
        {"$group": {"_id": "$label", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    return list(get_db().logs.aggregate(pipeline))


def dashboard_summary(user_email: str) -> dict[str, Any]:
    """Aggregates logs/alerts for one user (SOC dashboard)."""
    uf = _uf(user_email)
    db = get_db()
    logs = db.logs
    alerts = db.alerts

    total_flows = logs.count_documents(uf)
    normal_flows = logs.count_documents({**uf, "label": "Normal"})
    attack_flows = max(0, total_flows - normal_flows)
    active_alerts = alerts.count_documents({**uf, "analyst_status": "open"})

    since = utcnow() - timedelta(hours=24)
    bucket_map: dict[datetime, list[int]] = defaultdict(lambda: [0, 0])
    for doc in logs.find({**uf, "created_at": {"$gte": since}}, {"label": 1, "created_at": 1}):
        dt = doc["created_at"]
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        hour = dt.replace(minute=0, second=0, microsecond=0)
        if doc.get("label") == "Normal":
            bucket_map[hour][0] += 1
        else:
            bucket_map[hour][1] += 1

    now_floor = utcnow().replace(minute=0, second=0, microsecond=0)
    start_floor = now_floor - timedelta(hours=23)
    traffic_hourly: list[dict[str, Any]] = []
    for i in range(24):
        t = start_floor + timedelta(hours=i)
        n, a = bucket_map.get(t, [0, 0])
        traffic_hourly.append({"hour": f"{t.hour:02d}:00", "normal": n, "attack": a})

    breakdown_raw = aggregate_threat_counts(user_email)
    attack_distribution = [
        {"label": str(row["_id"]) if row["_id"] is not None else "Unknown", "count": int(row["count"])}
        for row in breakdown_raw
        if row.get("_id") != "Normal"
    ]

    recent_alerts_raw = list(alerts.find(uf).sort("created_at", -1).limit(20))
    recent_activity: list[dict[str, Any]] = []
    for doc in recent_alerts_raw:
        doc = _serialize(doc)
        created = doc.get("created_at") or ""
        time_part = created[11:19] if len(created) >= 19 else str(created)[:8]
        conf = float(doc.get("confidence") or 0)
        if conf >= 0.85:
            status = "Critical"
        elif conf >= 0.5:
            status = "Warning"
        else:
            status = "Warning"
        recent_activity.append(
            {
                "time": time_part,
                "source_ip": doc.get("source_ip") or "—",
                "dest_ip": "—",
                "type": str(doc.get("label") or "Unknown"),
                "status": status,
            }
        )

    highlight: dict[str, Any] | None = None
    cur_top = alerts.find({**uf, "label": {"$ne": "Normal"}}).sort("created_at", -1).limit(1)
    top = next(cur_top, None)
    if top is None:
        cur_top = alerts.find(uf).sort("created_at", -1).limit(1)
        top = next(cur_top, None)
    if top is not None:
        top = _serialize(top)
        lbl = top.get("label")
        if lbl and str(lbl) != "Normal":
            highlight = {
                "label": str(lbl),
                "confidence": float(top.get("confidence") or 0),
                "source_ip": top.get("source_ip"),
            }

    return {
        "metrics": {
            "total_flows": total_flows,
            "normal_flows": normal_flows,
            "attack_flows": attack_flows,
            "active_alerts": active_alerts,
        },
        "traffic_hourly": traffic_hourly,
        "attack_distribution": attack_distribution,
        "recent_activity": recent_activity,
        "highlight": highlight,
    }
