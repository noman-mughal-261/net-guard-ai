from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from pymongo import MongoClient, ReturnDocument

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


_users_index_ready = False


def ensure_users_index() -> None:
    global _users_index_ready
    if _users_index_ready:
        return
    get_db().users.create_index("email", unique=True)
    _users_index_ready = True


def _public_user(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "full_name": doc.get("full_name") or "",
        "email": doc.get("email") or "",
        "avatar_url": doc.get("avatar_url"),
    }


def create_user(email: str, full_name: str, password_hash: str) -> dict[str, Any]:
    ensure_users_index()
    key = _norm_email(email)
    now = utcnow()
    doc = {
        "email": key,
        "full_name": full_name.strip(),
        "password_hash": password_hash,
        "avatar_url": None,
        "created_at": now,
        "updated_at": now,
    }
    get_db().users.insert_one(doc)
    return _public_user(doc)


def get_user_by_email(email: str) -> dict[str, Any] | None:
    ensure_users_index()
    return get_db().users.find_one({"email": _norm_email(email)})


def update_user_profile(email: str, *, full_name: str | None = None, avatar_url: str | None = None) -> dict[str, Any] | None:
    ensure_users_index()
    updates: dict[str, Any] = {"updated_at": utcnow()}
    if full_name is not None:
        updates["full_name"] = full_name.strip()
    if avatar_url is not None:
        updates["avatar_url"] = avatar_url
    res = get_db().users.find_one_and_update(
        {"email": _norm_email(email)},
        {"$set": updates},
        return_document=ReturnDocument.AFTER,
    )
    return _public_user(res) if res else None


def update_user_password(email: str, password_hash: str) -> bool:
    ensure_users_index()
    res = get_db().users.update_one(
        {"email": _norm_email(email)},
        {"$set": {"password_hash": password_hash, "updated_at": utcnow()}},
    )
    return res.modified_count > 0 or res.matched_count > 0


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


def record_traffic_prediction(user_email: str, predicted_label: str) -> None:
    """
    Update lightweight counters for the dashboard.

    Important: we use these counters so we can avoid storing every flow in `logs`
    (which can overwhelm MongoDB). Detailed `logs` documents are still stored only
    for high-confidence attacks (see /api/analyze).
    """
    db = get_db()
    uf = _uf(user_email)

    hour = utcnow().replace(minute=0, second=0, microsecond=0)
    is_normal = predicted_label == "Normal"
    inc_normal = 1 if is_normal else 0
    inc_attack = 0 if is_normal else 1

    # Hourly bucket for the traffic graph (Normal vs Attack lines).
    db.traffic_hourly.update_one(
        {**uf, "hour": hour},
        {
            "$inc": {"normal": inc_normal, "attack": inc_attack},
            "$setOnInsert": {"normal": 0, "attack": 0, "hour": hour},
        },
        upsert=True,
    )

    # All-time totals for the dashboard metric cards.
    db.traffic_totals.update_one(
        uf,
        {
            "$inc": {"normal_flows": inc_normal, "attack_flows": inc_attack},
            "$setOnInsert": {"normal_flows": 0, "attack_flows": 0},
        },
        upsert=True,
    )

    # Per-label counts for the attack distribution pie.
    if not is_normal:
        db.traffic_label_counts.update_one(
            {**uf, "label": predicted_label},
            {"$inc": {"count": 1}},
            upsert=True,
        )


def _serialize(doc: dict) -> dict:
    out = dict(doc)
    if "_id" in out:
        out["_id"] = str(out["_id"])
    for k, v in list(out.items()):
        if isinstance(v, datetime):
            out[k] = v.isoformat()
    return out


def aggregate_threat_counts(user_email: str) -> list[dict]:
    """
    Returns items like: {"_id": "<label>", "count": <int>}

    Prefers traffic_label_counts counters (works even if we don't store all flows in `logs`).
    Falls back to aggregating `logs` for backward compatibility.
    """
    db = get_db()
    uf = _uf(user_email)

    if db.traffic_label_counts.find_one(uf) is not None:
        cur = db.traffic_label_counts.find(uf, {"label": 1, "count": 1})
        docs = list(cur)
        docs.sort(key=lambda d: int(d.get("count") or 0), reverse=True)
        return [{"_id": d.get("label"), "count": int(d.get("count") or 0)} for d in docs]

    # Fallback: older data path stores every flow as a log doc.
    pipeline = [
        {"$match": uf},
        {"$group": {"_id": "$label", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    return list(db.logs.aggregate(pipeline))


def dashboard_summary(user_email: str) -> dict[str, Any]:
    """Aggregates logs/alerts for one user (SOC dashboard)."""
    uf = _uf(user_email)
    db = get_db()
    logs = db.logs
    alerts = db.alerts

    # Prefer counter-based totals (works when we only store attack logs).
    totals_doc = db.traffic_totals.find_one(uf, {"normal_flows": 1, "attack_flows": 1})
    if totals_doc is not None:
        normal_flows = int(totals_doc.get("normal_flows") or 0)
        attack_flows = int(totals_doc.get("attack_flows") or 0)
        total_flows = normal_flows + attack_flows
    else:
        # Fallback for older deployments.
        total_flows = logs.count_documents(uf)
        normal_flows = logs.count_documents({**uf, "label": "Normal"})
        attack_flows = max(0, total_flows - normal_flows)
    active_alerts = alerts.count_documents({**uf, "analyst_status": "open"})

    bucket_map: dict[datetime, list[int]] = defaultdict(lambda: [0, 0])

    now_floor = utcnow().replace(minute=0, second=0, microsecond=0)
    start_floor = now_floor - timedelta(hours=23)

    # Prefer hourly counters (works when logs doesn't include every flow).
    for doc in db.traffic_hourly.find(
        {**uf, "hour": {"$gte": start_floor}},
        {"hour": 1, "normal": 1, "attack": 1},
    ):
        hour_dt = doc["hour"]
        if isinstance(hour_dt, str):
            hour_dt = datetime.fromisoformat(hour_dt.replace("Z", "+00:00"))
        bucket_map[hour_dt][0] = int(doc.get("normal") or 0)
        bucket_map[hour_dt][1] = int(doc.get("attack") or 0)

    # Fallback for older deployments (every flow stored as a log doc).
    if not bucket_map:
        since = utcnow() - timedelta(hours=24)
        for doc in logs.find({**uf, "created_at": {"$gte": since}}, {"label": 1, "created_at": 1}):
            dt = doc["created_at"]
            if isinstance(dt, str):
                dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            hour_dt = dt.replace(minute=0, second=0, microsecond=0)
            if doc.get("label") == "Normal":
                bucket_map[hour_dt][0] += 1
            else:
                bucket_map[hour_dt][1] += 1

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
