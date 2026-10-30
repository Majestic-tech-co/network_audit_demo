"""
Notification service.
Sends alerts when critical findings are detected.
Supports: Email (SMTP), Slack webhooks, Microsoft Teams webhooks.
"""
import asyncio
from typing import Optional
import httpx
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import structlog

from app.core.config import settings
from app.models.models import Finding, Device

log = structlog.get_logger()


def _severity_emoji(severity: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(severity, "⚪")


def _build_finding_summary(finding: Finding, device: Optional[Device]) -> dict:
    device_str = f"{device.hostname or device.ip_address}" if device else "Unknown device"
    return {
        "title": finding.title,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        "device": device_str,
        "description": finding.description[:300],
        "type": finding.finding_type,
        "emoji": _severity_emoji(str(finding.severity)),
    }


# ─── Email ────────────────────────────────────────────────────────

async def send_email_alert(finding: Finding, device: Optional[Device], recipients: list[str]):
    if not settings.SMTP_HOST or not recipients:
        return

    info = _build_finding_summary(finding, device)
    subject = f"{info['emoji']} [{info['severity'].upper()}] {info['title']} — NetAudit"

    html_body = f"""
    <html><body style="font-family: Arial, sans-serif; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #dc2626;">⚠️ Security Finding Detected</h2>
      <table style="width:100%; border-collapse:collapse; margin-bottom:16px;">
        <tr><td style="padding:8px; font-weight:bold; width:120px;">Severity</td>
            <td style="padding:8px;"><strong style="color:#dc2626;">{info['severity'].upper()}</strong></td></tr>
        <tr style="background:#f9f9f9;"><td style="padding:8px; font-weight:bold;">Device</td>
            <td style="padding:8px;">{info['device']}</td></tr>
        <tr><td style="padding:8px; font-weight:bold;">Finding</td>
            <td style="padding:8px;">{info['title']}</td></tr>
        <tr style="background:#f9f9f9;"><td style="padding:8px; font-weight:bold;">Type</td>
            <td style="padding:8px;">{info['type'].replace('_', ' ').title()}</td></tr>
      </table>
      <p style="color:#555;">{info['description']}</p>
      <p style="margin-top:24px; font-size:12px; color:#999;">
        Log in to your NetAudit dashboard to view AI-generated remediation steps.
      </p>
    </div>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html_body, "html"))

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
            use_tls=settings.SMTP_PORT == 465,
            start_tls=settings.SMTP_PORT == 587,
        )
        log.info("email_alert_sent", recipients=recipients, finding_id=str(finding.id))
    except Exception as e:
        log.error("email_alert_failed", error=str(e))


# ─── Slack ────────────────────────────────────────────────────────

async def send_slack_alert(finding: Finding, device: Optional[Device]):
    if not settings.SLACK_WEBHOOK_URL:
        return

    info = _build_finding_summary(finding, device)
    color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb"}.get(
        info["severity"], "#6b7280"
    )

    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{info['emoji']} *{info['severity'].upper()} — {info['title']}*\n"
                                f"*Device:* {info['device']}\n"
                                f"*Type:* {info['type'].replace('_', ' ').title()}\n\n"
                                f"{info['description']}",
                    },
                },
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": "NetAudit Security Platform"}],
                },
            ],
        }]
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(settings.SLACK_WEBHOOK_URL, json=payload)
            resp.raise_for_status()
        log.info("slack_alert_sent", finding_id=str(finding.id))
    except Exception as e:
        log.error("slack_alert_failed", error=str(e))


# ─── Microsoft Teams ──────────────────────────────────────────────

async def send_teams_alert(finding: Finding, device: Optional[Device]):
    if not settings.TEAMS_WEBHOOK_URL:
        return

    info = _build_finding_summary(finding, device)
    color = {"critical": "FF0000", "high": "FF6600", "medium": "FFA500", "low": "0066CC"}.get(
        info["severity"], "808080"
    )

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": f"{info['severity'].upper()}: {info['title']}",
        "sections": [{
            "activityTitle": f"{info['emoji']} {info['severity'].upper()} Security Finding",
            "activitySubtitle": f"Device: {info['device']}",
            "facts": [
                {"name": "Finding", "value": info["title"]},
                {"name": "Type", "value": info["type"].replace("_", " ").title()},
                {"name": "Severity", "value": info["severity"].upper()},
                {"name": "Description", "value": info["description"][:200]},
            ],
            "markdown": True,
        }],
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(settings.TEAMS_WEBHOOK_URL, json=payload)
            resp.raise_for_status()
        log.info("teams_alert_sent", finding_id=str(finding.id))
    except Exception as e:
        log.error("teams_alert_failed", error=str(e))


# ─── Unified dispatcher ────────────────────────────────────────────

async def notify_finding(
    finding: Finding,
    device: Optional[Device],
    email_recipients: Optional[list[str]] = None,
):
    """Send all configured notifications for a finding. Only alerts on critical/high."""
    severity = str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity)
    if severity not in ("critical", "high"):
        return

    tasks = []
    if email_recipients:
        tasks.append(send_email_alert(finding, device, email_recipients))
    tasks.append(send_slack_alert(finding, device))
    tasks.append(send_teams_alert(finding, device))

    await asyncio.gather(*tasks, return_exceptions=True)
