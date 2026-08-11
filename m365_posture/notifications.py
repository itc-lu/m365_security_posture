"""Outbound notifications: SMTP email plus Teams and Slack incoming webhooks.

Local-first design: nothing is sent unless an admin configures channels.
Global SMTP settings live in the ``app_settings`` table (key ``smtp``);
per-tenant channels and event toggles live in ``tool_configs`` under the
tool name ``notifications``. Every attempt is written to the
``notification_log`` table, which also powers digest de-duplication.

Events:
- ``run_failure``      — a scheduled/manual/CLI tool run failed
- ``score_regression`` — an import dropped the score beyond the threshold
                          (or produced per-area regressions)
- ``new_findings``     — an import introduced new actions
- ``risk_expiry``      — accepted risks have expired or expire within 14 days
                          (daily digest)
- ``test``             — "Send test notification" button
"""

from __future__ import annotations

import json
import smtplib
import ssl
from datetime import datetime, timedelta
from email.message import EmailMessage
from urllib.request import Request, urlopen

from .database import Database

EVENTS = ("run_failure", "score_regression", "new_findings", "risk_expiry")

DEFAULT_TENANT_CONFIG = {
    "enabled": False,
    "emails": [],           # list of recipient addresses
    "teams_webhook": "",    # Teams incoming-webhook / workflow URL
    "slack_webhook": "",    # Slack incoming-webhook URL
    "events": {e: True for e in EVENTS},
    "regression_threshold": 1.0,  # percentage points
}

DEFAULT_SMTP = {
    "host": "", "port": 587, "username": "", "password": "",
    "use_tls": True, "from_addr": "",
}

RISK_EXPIRY_LOOKAHEAD_DAYS = 14
_DIGEST_DEDUP_HOURS = 20
_WEBHOOK_TIMEOUT = 15
_SMTP_TIMEOUT = 15


def get_smtp_settings(db: Database) -> dict:
    settings = dict(DEFAULT_SMTP)
    settings.update(db.get_app_setting("smtp", {}))
    return settings


def get_notification_config(db: Database, tenant_name: str) -> dict:
    config = json.loads(json.dumps(DEFAULT_TENANT_CONFIG))  # deep copy
    stored = db.get_tool_config(tenant_name, "notifications")
    for key, value in (stored or {}).items():
        if key == "events" and isinstance(value, dict):
            config["events"].update(value)
        else:
            config[key] = value
    return config


def event_enabled(config: dict, event: str) -> bool:
    return bool(config.get("enabled")) and bool(config.get("events", {}).get(event, True))


# ── Channel senders (raise on failure) ──

def send_email(smtp_cfg: dict, recipients: list[str], subject: str, body: str):
    host = (smtp_cfg.get("host") or "").strip()
    if not host:
        raise RuntimeError("SMTP host is not configured")
    if not recipients:
        raise RuntimeError("No recipient addresses configured")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_cfg.get("from_addr") or smtp_cfg.get("username") or "m365-posture@localhost"
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    port = int(smtp_cfg.get("port") or 587)
    with smtplib.SMTP(host, port, timeout=_SMTP_TIMEOUT) as server:
        if smtp_cfg.get("use_tls", True):
            server.starttls(context=ssl.create_default_context())
        if smtp_cfg.get("username"):
            server.login(smtp_cfg["username"], smtp_cfg.get("password", ""))
        server.send_message(msg)


def send_webhook(url: str, subject: str, body: str):
    """POST a simple text payload — the format both classic Teams incoming
    webhooks and Slack incoming webhooks accept."""
    if not url or not url.lower().startswith("https://"):
        raise RuntimeError("Webhook URL must start with https://")
    payload = json.dumps({"text": f"**{subject}**\n\n{body}"}).encode()
    req = Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    with urlopen(req, timeout=_WEBHOOK_TIMEOUT) as resp:
        resp.read()


# ── Dispatch ──

def dispatch(db: Database, tenant_name: str, event: str, subject: str,
             body: str, config: dict | None = None, force: bool = False) -> dict:
    """Send one event through every configured channel.

    Never raises: channel errors are captured in the returned dict and the
    notification log so an import/run can never fail because a mail server
    is down. ``force=True`` skips the enabled/event checks (test button).
    """
    config = config if config is not None else get_notification_config(db, tenant_name)
    if not force and not event_enabled(config, event):
        return {"sent": 0, "skipped": True, "errors": []}

    sent = 0
    errors: list[str] = []

    channels = []
    if config.get("emails"):
        channels.append(("email", lambda: send_email(
            get_smtp_settings(db), list(config["emails"]), subject, body)))
    if config.get("teams_webhook"):
        channels.append(("teams", lambda: send_webhook(
            config["teams_webhook"], subject, body)))
    if config.get("slack_webhook"):
        channels.append(("slack", lambda: send_webhook(
            config["slack_webhook"], subject, body)))

    if not channels:
        return {"sent": 0, "skipped": True,
                "errors": ["No channels configured (emails / Teams / Slack)"]}

    for name, send in channels:
        try:
            send()
            db.add_notification_log(tenant_name, event, name, "sent", subject)
            sent += 1
        except Exception as e:  # noqa: BLE001 — must never break the caller
            db.add_notification_log(tenant_name, event, name, "error",
                                    f"{subject} — {e}")
            errors.append(f"{name}: {e}")

    return {"sent": sent, "skipped": False, "errors": errors}


# ── Event helpers ──

def _tenant_label(db: Database, tenant_name: str) -> str:
    tenant = db.get_tenant(tenant_name) or {}
    return tenant.get("display_name") or tenant_name


def notify_run_failure(db: Database, tenant_name: str, task_type: str,
                       detail: str) -> dict:
    label = _tenant_label(db, tenant_name)
    subject = f"[{label}] Automation run failed: {task_type}"
    body = (f"The {task_type} run for tenant '{label}' failed.\n\n"
            f"{(detail or '(no detail)')[:3000]}\n\n"
            "Full output: Automation page > Run History.")
    return dispatch(db, tenant_name, "run_failure", subject, body)


def notify_import_events(db: Database, tenant_name: str, result: dict) -> dict:
    """After an import: regression + new-findings notifications."""
    config = get_notification_config(db, tenant_name)
    outcome = {"sent": 0, "errors": []}
    label = _tenant_label(db, tenant_name)

    drift = result.get("drift") or {}
    threshold = float(config.get("regression_threshold", 1.0) or 0)
    delta = drift.get("score_delta") or 0
    regressions = drift.get("regressions") or []
    if event_enabled(config, "score_regression") and (
            delta <= -threshold or regressions):
        lines = [f"Overall score change: {delta:+.2f}%"
                 f" (now {drift.get('current_percentage', '?')}%)."]
        for r in regressions[:10]:
            lines.append(f"- {r.get('scope', '?')}: "
                         f"{r.get('old_value', '?')}% → {r.get('new_value', '?')}% "
                         f"({r.get('delta', 0):+.2f}%)")
        subject = f"[{label}] Security score regressed"
        sub_result = dispatch(db, tenant_name, "score_regression", subject,
                              "\n".join(lines), config)
        outcome["sent"] += sub_result["sent"]
        outcome["errors"].extend(sub_result["errors"])

    new_count = result.get("new_actions") or 0
    if event_enabled(config, "new_findings") and new_count > 0:
        subject = f"[{label}] {new_count} new finding(s) imported"
        body = (f"The latest {result.get('source', 'import')} import added "
                f"{new_count} new action(s) "
                f"({result.get('total_parsed', '?')} parsed in total).\n"
                "Review them on the Actions page.")
        sub_result = dispatch(db, tenant_name, "new_findings", subject, body, config)
        outcome["sent"] += sub_result["sent"]
        outcome["errors"].extend(sub_result["errors"])

    return outcome


def notify_risk_expiry_digest(db: Database, tenant_name: str) -> dict:
    """Daily digest of expired / soon-expiring risk acceptances."""
    config = get_notification_config(db, tenant_name)
    if not event_enabled(config, "risk_expiry"):
        return {"sent": 0, "skipped": True, "errors": []}
    if db.was_recently_notified(tenant_name, "risk_expiry", _DIGEST_DEDUP_HOURS):
        return {"sent": 0, "skipped": True, "errors": []}

    now = datetime.utcnow()
    cutoff = (now + timedelta(days=RISK_EXPIRY_LOOKAHEAD_DAYS)).isoformat()
    accepted = db.get_actions(tenant_name, {"status": "Risk Accepted"})
    expiring = [a for a in accepted
                if a.get("risk_expiry_date") and a["risk_expiry_date"] <= cutoff]
    if not expiring:
        return {"sent": 0, "skipped": True, "errors": []}

    label = _tenant_label(db, tenant_name)
    now_iso = now.isoformat()
    lines = []
    for a in sorted(expiring, key=lambda x: x.get("risk_expiry_date") or ""):
        state = "EXPIRED" if (a.get("risk_expiry_date") or "") <= now_iso else "expires"
        lines.append(f"- [{state} {str(a.get('risk_expiry_date'))[:10]}] "
                     f"{a.get('title', '')[:90]} (owner: {a.get('risk_owner') or '—'})")
    subject = f"[{label}] {len(expiring)} risk acceptance(s) expired or expiring soon"
    body = ("The following accepted risks are past or within "
            f"{RISK_EXPIRY_LOOKAHEAD_DAYS} days of their expiry date:\n\n"
            + "\n".join(lines)
            + "\n\nExpired acceptances revert to ToDo automatically; review "
              "them in the Risk Register.")
    return dispatch(db, tenant_name, "risk_expiry", subject, body, config)


def run_risk_expiry_checks(db: Database) -> dict:
    """Scheduler entry point: run the digest for every tenant that opted in."""
    results = {}
    for tenant in db.list_tenants():
        name = tenant["name"]
        try:
            results[name] = notify_risk_expiry_digest(db, name)
        except Exception as e:  # noqa: BLE001 — keep the scheduler alive
            results[name] = {"sent": 0, "errors": [str(e)]}
    return results


def send_test_notification(db: Database, tenant_name: str) -> dict:
    """Used by the 'Send test notification' button. Bypasses event toggles
    but still requires channels to be configured."""
    label = _tenant_label(db, tenant_name)
    return dispatch(
        db, tenant_name, "test",
        f"[{label}] Test notification",
        "This is a test notification from the M365 Security Posture tool. "
        "Channel configuration works.",
        force=True)
