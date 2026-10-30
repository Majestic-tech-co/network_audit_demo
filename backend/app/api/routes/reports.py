"""
Report export routes.
GET /api/scans/{id}/report.pdf  — download PDF report for a scan
GET /api/scans/{id}/report.json — structured JSON export
"""
from xml.sax.saxutils import escape as xml_escape

from fastapi import Request, APIRouter, Depends, HTTPException
from fastapi.responses import Response, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from uuid import UUID

from app.core.limiter import limiter
from app.db.session import get_db
from app.models.models import Scan, Finding, Device, Organization, User, ScanStatus
from app.core.auth import get_current_it_user
from app.services.pdf_report import generate_pdf

import structlog

log = structlog.get_logger()
router = APIRouter(prefix="/api/scans", tags=["reports"])


def _pdf_safe(value):
    """reportlab Paragraph parses XML-like markup (<img src=...>, <a>); scan data comes from
    network banners and agents, so escape every string before it reaches the PDF."""
    if isinstance(value, str):
        return xml_escape(value)
    if isinstance(value, dict):
        return {k: _pdf_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_pdf_safe(v) for v in value]
    return value


async def _load_scan_data(scan_id: UUID, org_id, db: AsyncSession) -> tuple:
    """Load scan + findings + devices for report generation."""
    # Load scan
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.organization_id == org_id)
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Report only available for completed scans")

    # Load findings with device info
    findings_result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .options(selectinload(Finding.device))
        .order_by(Finding.severity.desc())
    )
    findings = findings_result.scalars().all()

    # Load all devices discovered in this scan
    device_ids = {f.device_id for f in findings if f.device_id}
    devices = []
    if device_ids:
        devices_result = await db.execute(
            select(Device)
            .where(Device.id.in_(device_ids))
            .options(selectinload(Device.ports))
        )
        devices = devices_result.scalars().all()

    # Load org name
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()

    return scan, findings, devices, org


@router.get("/{scan_id}/report.pdf")
@limiter.limit("10/minute")
async def download_pdf_report(
    request: Request,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    scan, findings, devices, org = await _load_scan_data(
        scan_id, current_user.organization_id, db
    )

    # Build flat dicts for the template
    findings_data = [
        {
            "title": f.title,
            "severity": str(f.severity.value if hasattr(f.severity, "value") else f.severity),
            "finding_type": f.finding_type,
            "description": f.description,
            "device_ip": f.device.ip_address if f.device else "Unknown",
            "device_hostname": f.device.hostname if f.device else None,
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "virus_name": f.virus_name,
            "file_path": f.file_path,
            "ai_remediation": f.ai_remediation,
        }
        for f in findings
    ]

    devices_data = [
        {
            "ip_address": d.ip_address,
            "hostname": d.hostname,
            "os_guess": d.os_guess,
            "device_type": d.device_type,
            "port_count": len(d.ports),
            "risk_score": d.risk_score,
            "first_seen": d.first_seen.strftime("%Y-%m-%d") if d.first_seen else "—",
        }
        for d in devices
    ]

    scan_data = {
        "target": scan.target,
        "scan_type": scan.scan_type,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "hosts_discovered": scan.hosts_discovered,
    }

    initiated_by = current_user.username
    if scan.initiated_by_id:
        # Could load the initiating user's name here if needed
        pass

    try:
        pdf_bytes = generate_pdf(
            scan=_pdf_safe(scan_data),
            findings=_pdf_safe(findings_data),
            devices=_pdf_safe(devices_data),
            org_name=_pdf_safe(org.name if org else "Your Organization"),
            initiated_by=_pdf_safe(initiated_by),
            org_logo_data=org.logo_data if org else None,
        )
    except Exception as e:
        log.error("pdf_generation_failed", error=str(e))
        raise HTTPException(status_code=500, detail="PDF generation failed")

    filename = f"netaudit-report-{scan.target.replace('/', '-')}-{scan.created_at.strftime('%Y%m%d')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/report.json")
@limiter.limit("30/minute")
async def download_json_report(
    request: Request,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    """Machine-readable JSON export for integration with other tools."""
    scan, findings, devices, org = await _load_scan_data(
        scan_id, current_user.organization_id, db
    )

    return JSONResponse({
        "report_version": "1.0",
        "generated_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "organization": org.name if org else None,
        "scan": {
            "id": str(scan.id),
            "target": scan.target,
            "type": str(scan.scan_type),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "hosts_discovered": scan.hosts_discovered,
            "findings_count": scan.findings_count,
        },
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": str(f.severity.value if hasattr(f.severity, "value") else f.severity),
                "type": f.finding_type,
                "status": str(f.status),
                "description": f.description,
                "device_ip": f.device.ip_address if f.device else None,
                "cve_id": f.cve_id,
                "cvss_score": f.cvss_score,
                "virus_name": f.virus_name,
                "ai_remediation": f.ai_remediation,
            }
            for f in findings
        ],
        "devices": [
            {
                "ip": d.ip_address,
                "hostname": d.hostname,
                "os": d.os_guess,
                "risk_score": d.risk_score,
                "ports": [
                    {"port": p.port_number, "protocol": p.protocol, "service": p.service_name}
                    for p in d.ports
                ],
            }
            for d in devices
        ],
    })
