from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from random import choice, random, randint
from time import time

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pymongo.errors import DuplicateKeyError

from .config import get_settings
from .db import (
    get_client,
    add_blocked_ip,
    aggregate_threat_counts,
    create_user,
    dashboard_summary,
    get_user_by_email,
    insert_alert,
    insert_audit,
    insert_log,
    is_ip_blocked,
    list_alerts,
    list_audit,
    list_blocked_ips,
    list_logs,
    update_alert_status,
    update_user_password,
    update_user_profile,
    record_traffic_prediction,
)
from .email_alerts import send_attack_alert
from .firewall import apply_iptables_drop
from .ip_policy import is_blocked_target
from .ml_inference import load_metrics, ml_service
from .passwords import hash_password, verify_password
from .profile import save_avatar
from .schemas import (
    AlertActionRequest,
    AnalyzeRequest,
    BlockIpRequest,
    LoginRequest,
    PasswordChangeRequest,
    ProfileUpdateRequest,
    SignupRequest,
)
from .security import require_user_email


def _user_public(doc: dict) -> dict:
    return {
        "full_name": doc.get("full_name") or "",
        "email": doc.get("email") or "",
        "avatar_url": doc.get("avatar_url"),
    }


def _auth_token(email: str) -> str:
    return f"demo-token-{email}"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ml_service.load()
    upload_root = Path(get_settings()["upload_dir"])
    (upload_root / "avatars").mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="NetGuard AI SOC API", version="1.0.0", lifespan=lifespan)

_settings = get_settings()
_scan_sessions: dict[str, dict[str, object]] = {}
_threat_names = ["Tracker.exe", "Trojan.Bat", "Worm.autorun.exe", "Backdoor.X", "Ransom.Lock"]
_threat_types = ["Spyware", "Malware", "Worm", "Trojan", "Ransomware"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings["cors_origins"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_upload_root = Path(_settings["upload_dir"])
_upload_root.mkdir(parents=True, exist_ok=True)
(_upload_root / "avatars").mkdir(parents=True, exist_ok=True)
app.mount("/api/uploads", StaticFiles(directory=str(_upload_root)), name="uploads")


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


@app.post("/signup")
@app.post("/api/signup")
def signup(body: SignupRequest):
    key = body.email.lower().strip()
    try:
        user = create_user(key, body.full_name, hash_password(body.password))
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Email already exists") from None
    return {
        "ok": True,
        "message": "Account created",
        "user": user,
        "token": _auth_token(key),
    }


@app.post("/login")
@app.post("/api/login")
def login(body: LoginRequest):
    key = body.email.lower().strip()
    user = get_user_by_email(key)
    if not user or not verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"ok": True, "token": _auth_token(key), "user": _user_public(user)}


@app.get("/api/me")
def me(user_email: str = Depends(require_user_email)):
    user = get_user_by_email(user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True, "user": _user_public(user)}


@app.patch("/api/profile")
def update_profile(body: ProfileUpdateRequest, user_email: str = Depends(require_user_email)):
    updated = update_user_profile(user_email, full_name=body.full_name)
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True, "user": updated}


@app.patch("/api/profile/password")
def change_password(body: PasswordChangeRequest, user_email: str = Depends(require_user_email)):
    if body.current_password == body.new_password:
        raise HTTPException(status_code=400, detail="New password must differ from current password")
    user = get_user_by_email(user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(body.current_password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if not update_user_password(user_email, hash_password(body.new_password)):
        raise HTTPException(status_code=500, detail="Failed to update password")
    return {"ok": True, "message": "Password updated"}


@app.post("/api/profile/avatar")
def upload_avatar(
    file: UploadFile = File(...),
    user_email: str = Depends(require_user_email),
):
    avatar_url = save_avatar(user_email, file)
    user = get_user_by_email(user_email)
    return {"ok": True, "avatar_url": avatar_url, "user": _user_public(user) if user else None}


@app.post("/scan")
@app.post("/api/scan")
def scan(user_email: str = Depends(require_user_email)):
    session_id = f"sess-{int(time() * 1000)}-{randint(100, 999)}"
    threat_count = randint(0, 4)
    threats: list[dict[str, str]] = []
    for _ in range(threat_count):
        threats.append(
            {
                "name": choice(_threat_names),
                "type": choice(_threat_types),
                "time": f"{randint(10, 59)}:{randint(10, 59)} AM",
            }
        )
    _scan_sessions[session_id] = {
        "user_email": user_email,
        "started_at": time(),
        "duration": randint(6, 12),
        "threats": threats,
        "device_name": "My PC",
        "ip": f"192.168.1.{randint(2, 240)}",
    }
    return {"ok": True, "session_id": session_id}


@app.get("/api/scan/{session_id}")
def scan_progress(session_id: str, user_email: str = Depends(require_user_email)):
    session = _scan_sessions.get(session_id)
    if not session or session.get("user_email") != user_email:
        raise HTTPException(status_code=404, detail="Scan session not found")
    elapsed = time() - float(session["started_at"])
    duration = float(session["duration"])
    progress = min(100, int((elapsed / duration) * 100))
    done = progress >= 100
    status = "complete" if done else "scanning"
    return {
        "session_id": session_id,
        "status": status,
        "progress": progress,
        "result": {
            "device_name": session["device_name"],
            "device_ip": session["ip"],
            "firewall_status": "Enabled",
            "threats": session["threats"] if done else [],
            "issues_found": len(session["threats"]) if done else 0,
            "system_status": "Threat Detected" if done and len(session["threats"]) > 0 else "Secure",
        },
    }


@app.get("/history")
@app.get("/api/history")
def history(limit: int = 10, user_email: str = Depends(require_user_email)):
    items: list[dict[str, object]] = []
    for idx, alert in enumerate(list_alerts(user_email, limit=limit), start=1):
        items.append(
            {
                "id": alert["_id"],
                "device_name": f"My PC {idx}",
                "date_time": alert.get("created_at"),
                "threats_identified": 1 if alert.get("label") and alert.get("label") != "Normal" else 0,
                "device_details": {
                    "ip": alert.get("source_ip") or "192.168.1.101",
                    "firewall_status": "Enabled",
                },
                "threats": [
                    {
                        "name": alert.get("label", "Unknown"),
                        "type": "Anomaly",
                        "time": str(alert.get("created_at", ""))[11:19],
                    }
                ],
            }
        )
    return {"items": items}


@app.post("/api/analyze")
def analyze(body: AnalyzeRequest, user_email: str = Depends(require_user_email)):
    try:
        pred = ml_service.predict_from_features(body.features)
        print("Body",body)
        print("ML Prediction",pred)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {e}") from e

    threshold = _settings["alert_confidence_threshold"]
    is_attack = pred["label"] != "Normal"
    should_alert = is_attack and pred["confidence"] >= threshold

    # Always update counters so the dashboard can show real traffic
    # without storing every flow document in MongoDB.
    record_traffic_prediction(user_email, pred["label"])

    #log_id = None
    # Store detailed `logs` only when the model predicts an attack label
    # (label != "Normal"). This keeps DB size manageable while still
    # preserving attack context for analysis.
   # if is_attack:
    #    log_doc = {
     #       "source_ip": body.source_ip,
      #      "label": pred["label"],
       #     "confidence": pred["confidence"],
        #    "probabilities": pred["probabilities"],
         #   "features": body.features,
          #  "alert_triggered": should_alert,
        #}
        #log_id = insert_log(log_doc, user_email)

    log_doc = {
         "source_ip": body.source_ip,
            "label": pred["label"],
            "confidence": pred["confidence"],
            "probabilities": pred["probabilities"],
            "features": body.features,
            "alert_triggered": should_alert,
     }
    log_id= insert_log(log_doc,user_email)
    
    alert_id = None
    if should_alert:
        alert_doc = {
            "source_ip": body.source_ip,
            "label": pred["label"],
            "confidence": pred["confidence"],
            "probabilities": pred["probabilities"],
            "log_id": log_id,
        }
        alert_id = insert_alert(alert_doc, user_email)
        ok, msg = send_attack_alert(
            label=pred["label"],
            confidence=pred["confidence"],
            source_ip=body.source_ip,
            log_id=log_id,
            recipient_email=user_email,
        )
        if not ok:
            insert_audit(
                {
                    "action": "email_alert_failed",
                    "detail": msg,
                    "log_id": log_id,
                    "alert_id": alert_id,
                },
                user_email,
            )
            print("Alert Faliure Details",msg)

    return {
        "label": pred["label"],
        "confidence": pred["confidence"],
        "probabilities": pred["probabilities"],
        "log_id": log_id,
        "alert_id": alert_id,
        "alert_triggered": should_alert,
    }


@app.get("/api/logs")
def api_logs(limit: int = 200, user_email: str = Depends(require_user_email)):
    return {"items": list_logs(user_email, limit=limit)}


@app.get("/api/alerts")
def api_alerts(limit: int = 100, user_email: str = Depends(require_user_email)):
    return {"items": list_alerts(user_email, limit=limit)}


@app.post("/api/alert-action")
def alert_action(body: AlertActionRequest, user_email: str = Depends(require_user_email)):
    action = body.action.lower().strip()
    if action not in ("monitor", "ignore"):
        raise HTTPException(status_code=400, detail="action must be monitor or ignore")
    status = "monitoring" if action == "monitor" else "ignored"
    ok = update_alert_status(body.alert_id, status, user_email)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    insert_audit(
        {
            "action": f"alert_{action}",
            "alert_id": body.alert_id,
            "new_status": status,
        },
        user_email,
    )
    return {"ok": True, "alert_id": body.alert_id, "analyst_status": status}


@app.post("/api/block-ip")
def block_ip(body: BlockIpRequest, user_email: str = Depends(require_user_email)):
    allowed, reason = is_blocked_target(body.ip)
    if not allowed:
        insert_audit(
            {
                "action": "block_denied",
                "ip": body.ip,
                "reason": reason,
                "analyst": body.analyst,
            },
            user_email,
        )
        raise HTTPException(status_code=400, detail=reason)

    if is_ip_blocked(body.ip, user_email):
        insert_audit(
            {
                "action": "block_duplicate",
                "ip": body.ip,
                "analyst": body.analyst,
            },
            user_email,
        )
        return {"ok": True, "ip": body.ip, "already_blocked": True}

    fw_ok, fw_msg = apply_iptables_drop(body.ip)
    add_blocked_ip(
        body.ip,
        user_email,
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
        },
        user_email,
    )
    return {
        "ok": True,
        "ip": body.ip,
        "firewall_applied": fw_ok,
        "firewall_message": fw_msg,
    }


@app.get("/api/blocked-ips")
def blocked_ips(user_email: str = Depends(require_user_email)):
    return {"items": list_blocked_ips(user_email)}


@app.get("/api/model-performance")
def model_performance():
    m = load_metrics()
    if not m:
        raise HTTPException(status_code=404, detail="model_metrics.json not found")
    return m


@app.get("/api/analytics/summary")
def analytics_summary(user_email: str = Depends(require_user_email)):
    breakdown = aggregate_threat_counts(user_email)
    return {"threat_breakdown": breakdown}


@app.get("/api/dashboard/summary")
def api_dashboard_summary(user_email: str = Depends(require_user_email)):
    """Metrics, hourly traffic, attack mix, recent alerts, and top highlight for the dashboard UI."""
    return dashboard_summary(user_email)


@app.get("/api/audit-logs")
def audit_logs(limit: int = 50, user_email: str = Depends(require_user_email)):
    return {"items": list_audit(user_email, limit=limit)}
