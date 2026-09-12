from __future__ import annotations

import smtplib
from email.message import EmailMessage

from .config import get_settings


def send_attack_alert(
    *,
    label: str,
    confidence: float,
    source_ip: str | None,
    log_id: str | None,
    recipient_email: str,
) -> tuple[bool, str]:
    s = get_settings()
    print("Email Data",label,confidence,source_ip,log_id,recipient_email)
    if not s["smtp_host"] or not recipient_email:
        return False, "SMTP not configured"
    msg = EmailMessage()
    msg["Subject"] = f"[NetGuard AI] High-confidence attack: {label}"
    msg["From"] = s["smtp_from"] or s["smtp_user"] or "netguard@localhost"
    msg["To"] = recipient_email
    body = (
        f"Threat: {label}\n"
        f"Confidence: {confidence:.4f}\n"
        f"Source IP: {source_ip or 'n/a'}\n"
        f"Log ID: {log_id or 'n/a'}\n"
    )
    msg.set_content(body)
    try:
        if s["smtp_use_tls"]:
            with smtplib.SMTP(s["smtp_host"], s["smtp_port"], timeout=30) as server:
                server.starttls()
                if s["smtp_user"] and s["smtp_password"]:
                    server.login(s["smtp_user"], s["smtp_password"])
                server.send_message(msg)
        else:
            with smtplib.SMTP(s["smtp_host"], s["smtp_port"], timeout=30) as server:
                if s["smtp_user"] and s["smtp_password"]:
                    server.login(s["smtp_user"], s["smtp_password"])
                server.send_message(msg)
        return True, "sent"
    except Exception as e:
        return False, str(e)
