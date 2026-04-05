from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .db import (
    get_client,
    add_blocked_ip,
    aggregate_threat_counts,
    insert_alert,
    insert_audit,
    insert_log,
    is_ip_blocked,
    list_alerts,
    list_audit,
    list_blocked_ips,
    list_logs,
    update_alert_status,
)
from .email_alerts import send_attack_alert
from .firewall import apply_iptables_drop
from .ip_policy import is_blocked_target
from .ml_inference import load_metrics, ml_service
from .schemas import AlertActionRequest, AnalyzeRequest, BlockIpRequest
from .security import require_block_api_key


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ml_service.load()
    yield


app = FastAPI(title="NetGuard AI SOC API", version="1.0.0", lifespan=lifespan)

_settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings["cors_origins"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    mongo_ok = False
    try:
        get_client().admin.command("ping", maxTimeMS=2000)
        mongo_ok = True
    except Exception:
        pass
    return {
        "status": "ok" if mongo_ok else "degraded",
        "service": "netguard-ai",
        "mongodb": mongo_ok,
        "model_loaded": ml_service.is_loaded,
    }


@app.post("/api/analyze")
def analyze(body: AnalyzeRequest):
    try:
        pred = ml_service.predict_from_features(body.features)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {e}") from e

    threshold = _settings["alert_confidence_threshold"]
    is_attack = pred["label"] != "Normal"
    should_alert = is_attack and pred["confidence"] >= threshold

    log_doc = {
        "source_ip": body.source_ip,
        "label": pred["label"],
        "confidence": pred["confidence"],
        "probabilities": pred["probabilities"],
        "features": body.features,
        "alert_triggered": should_alert,
    }
    log_id = insert_log(log_doc)

    alert_id = None
    if should_alert:
        alert_doc = {
            "source_ip": body.source_ip,
            "label": pred["label"],
            "confidence": pred["confidence"],
            "probabilities": pred["probabilities"],
            "log_id": log_id,
        }
        alert_id = insert_alert(alert_doc)
        ok, msg = send_attack_alert(
            label=pred["label"],
            confidence=pred["confidence"],
            source_ip=body.source_ip,
            log_id=log_id,
        )
        if not ok:
            insert_audit(
                {
                    "action": "email_alert_failed",
                    "detail": msg,
                    "log_id": log_id,
                    "alert_id": alert_id,
                }
            )

    return {
        "label": pred["label"],
        "confidence": pred["confidence"],
        "probabilities": pred["probabilities"],
        "log_id": log_id,
        "alert_id": alert_id,
        "alert_triggered": should_alert,
    }


@app.get("/api/logs")
def api_logs(limit: int = 200):
    return {"items": list_logs(limit=limit)}


@app.get("/api/alerts")
def api_alerts(limit: int = 100):
    return {"items": list_alerts(limit=limit)}


@app.post("/api/alert-action")
def alert_action(body: AlertActionRequest):
    action = body.action.lower().strip()
    if action not in ("monitor", "ignore"):
        raise HTTPException(status_code=400, detail="action must be monitor or ignore")
    status = "monitoring" if action == "monitor" else "ignored"
    ok = update_alert_status(body.alert_id, status)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    insert_audit(
        {
            "action": f"alert_{action}",
            "alert_id": body.alert_id,
            "new_status": status,
        }
    )
    return {"ok": True, "alert_id": body.alert_id, "analyst_status": status}


@app.post("/api/block-ip")
def block_ip(body: BlockIpRequest, _api_key: str = Depends(require_block_api_key)):
    allowed, reason = is_blocked_target(body.ip)
    if not allowed:
        insert_audit(
            {
                "action": "block_denied",
                "ip": body.ip,
                "reason": reason,
                "analyst": body.analyst,
            }
        )
        raise HTTPException(status_code=400, detail=reason)

    if is_ip_blocked(body.ip):
        insert_audit(
            {
                "action": "block_duplicate",
                "ip": body.ip,
                "analyst": body.analyst,
            }
        )
        return {"ok": True, "ip": body.ip, "already_blocked": True}

    fw_ok, fw_msg = apply_iptables_drop(body.ip)
    add_blocked_ip(
        body.ip,
        analyst=body.analyst,
        reason=body.reason,
        firewall_ok=fw_ok,
        firewall_message=fw_msg,
    )
    insert_audit(
        {
            "action": "block_ip",
            "ip": body.ip,
            "analyst": body.analyst,
            "reason": body.reason,
            "firewall_applied": fw_ok,
            "firewall_message": fw_msg,
        }
    )
    return {
        "ok": True,
        "ip": body.ip,
        "firewall_applied": fw_ok,
        "firewall_message": fw_msg,
    }


@app.get("/api/blocked-ips")
def blocked_ips():
    return {"items": list_blocked_ips()}


@app.get("/api/model-performance")
def model_performance():
    m = load_metrics()
    if not m:
        raise HTTPException(status_code=404, detail="model_metrics.json not found")
    return m


@app.get("/api/analytics/summary")
def analytics_summary():
    breakdown = aggregate_threat_counts()
    return {"threat_breakdown": breakdown}


@app.get("/api/audit-logs")
def audit_logs(limit: int = 50):
    return {"items": list_audit(limit=limit)}
