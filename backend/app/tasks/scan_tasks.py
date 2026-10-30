"""
Celery tasks for scan execution and AI remediation.
These run in the worker container, not the API container.

Async pattern: each Celery task is synchronous but spins up its own
event loop via asyncio.run(). This is the correct pattern for Celery
workers — never share an event loop across tasks.
"""
import asyncio
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, delete as sa_delete
from sqlalchemy.orm import selectinload
import structlog

from app.tasks.celery_app import celery_app
from app.db.session import AsyncSessionLocal
from app.models.models import (
    Scan, Device, Port, Finding, Organization,
    ScanStatus, Severity, FindingStatus
)
from app.core.security import decrypt
from app.core.websocket import publish_scan_event
from app.services.scanner.scan_service import NmapScanService, VirusScanService, infer_device_type
from app.services.ai_providers.service import AIService

log = structlog.get_logger()


def _uuid(value):
    """Celery passes ids as JSON strings; the UUID columns want UUID objects."""
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


@celery_app.task(name="run_network_scan", max_retries=1, bind=True)
def run_network_scan(self, scan_id: str, scan_type: str, target: str, options: dict):
    log.info("scan_task_started", scan_id=scan_id, type=scan_type, target=target)
    try:
        asyncio.run(_run_network_scan_async(scan_id, scan_type, target, options))
    except Exception as exc:
        log.error("scan_task_failed", scan_id=scan_id, error=str(exc))
        if self.request.retries < 1:
            raise self.retry(exc=exc, countdown=10)
        raise


async def _run_network_scan_async(scan_id: str, scan_type: str, target: str, options: dict):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == _uuid(scan_id)))
        scan = result.scalar_one_or_none()
        if not scan:
            log.error("scan_not_found", scan_id=scan_id)
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

        # Notify clients scan has started
        publish_scan_event(str(scan.organization_id), "scan_started", scan_id, {
            "scan_type": scan_type,
            "target": target,
            "message": f"Scan started on {target}",
        })

        try:
            nmap_service = NmapScanService()

            publish_scan_event(str(scan.organization_id), "scan_progress", scan_id, {
                "percent": 10,
                "message": f"Running {scan_type} on {target}…",
            })

            scan_results = await nmap_service.run_scan(scan, scan_type, target)
            hosts = scan_results.get("hosts", [])
            scan.hosts_discovered = len(hosts)
            scan.raw_output_path = scan_results.get("raw_output_path")

            publish_scan_event(str(scan.organization_id), "scan_progress", scan_id, {
                "percent": 60,
                "message": f"Discovered {len(hosts)} hosts. Analysing findings…",
                "hosts_found": len(hosts),
            })

            total_findings = 0
            for i, host_data in enumerate(hosts):
                device = await _upsert_device(db, scan.organization_id, host_data)
                await _clear_device_findings(db, device.id)
                total_findings += await _create_findings_from_host(db, scan, device, host_data)
                device.risk_score = _calculate_risk_score(host_data.get("findings", []))
                device.last_seen = datetime.now(timezone.utc)

                # Incremental progress per host
                pct = 60 + int(30 * (i + 1) / max(len(hosts), 1))
                publish_scan_event(str(scan.organization_id), "scan_progress", scan_id, {
                    "percent": pct,
                    "message": f"Processed {i+1}/{len(hosts)} hosts…",
                })

            scan.findings_count = total_findings
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()

            publish_scan_event(str(scan.organization_id), "scan_complete", scan_id, {
                "percent": 100,
                "hosts_discovered": len(hosts),
                "findings_count": total_findings,
                "message": f"Scan complete — {len(hosts)} hosts, {total_findings} findings",
            })

            log.info("scan_completed", scan_id=scan_id, hosts=len(hosts), findings=total_findings)

            # Send notifications for critical/high findings (gathered concurrently)
            if total_findings > 0:
                from app.services.notifications import notify_finding
                import asyncio as _asyncio
                all_findings_r = await db.execute(
                    select(Finding)
                    .where(Finding.scan_id == scan.id)
                    .options(selectinload(Finding.device))
                )
                notify_tasks = [
                    notify_finding(f, f.device)
                    for f in all_findings_r.scalars().all()
                ]
                await _asyncio.gather(*notify_tasks, return_exceptions=True)

        except Exception as e:
            log.error("scan_failed", scan_id=scan_id, error=str(e))
            publish_scan_event(str(scan.organization_id), "scan_failed", scan_id, {
                "message": "Scan failed. Check the server logs for details.",
            })
            await db.rollback()
            async with AsyncSessionLocal() as db2:
                r = await db2.execute(select(Scan).where(Scan.id == _uuid(scan_id)))
                s = r.scalar_one_or_none()
                if s:
                    s.status = ScanStatus.FAILED
                    s.error_message = "Scan failed. Check the server logs for details."
                    s.completed_at = datetime.now(timezone.utc)
                    await db2.commit()
            raise


async def _upsert_device(db, org_id, host_data: dict) -> Device:
    ip = host_data["ip"]
    result = await db.execute(
        select(Device).where(Device.organization_id == org_id, Device.ip_address == ip)
    )
    device = result.scalar_one_or_none()
    os_info = host_data.get("os", {})
    now = datetime.now(timezone.utc)
    hostname = host_data.get("hostname")
    device_type = infer_device_type(hostname, os_info.get("type"))
    if device:
        device.hostname = hostname or device.hostname
        device.os_guess = os_info.get("name") or device.os_guess
        device.os_confidence = os_info.get("accuracy") or device.os_confidence
        device.device_type = device_type
        device.last_seen = now
    else:
        device = Device(
            organization_id=org_id,
            ip_address=ip,
            hostname=hostname,
            os_guess=os_info.get("name"),
            os_confidence=os_info.get("accuracy"),
            device_type=device_type,
            first_seen=now,
            last_seen=now,
        )
        db.add(device)
    await db.flush()
    for port_data in host_data.get("ports", []):
        port_result = await db.execute(
            select(Port).where(
                Port.device_id == device.id,
                Port.port_number == port_data["port"],
                Port.protocol == port_data.get("protocol", "tcp"),
            )
        )
        port = port_result.scalar_one_or_none()
        if port:
            port.state = port_data.get("state", "open")
            port.service_name = port_data.get("service")
            port.service_version = port_data.get("version")
            port.last_seen = now
        else:
            db.add(Port(
                device_id=device.id,
                port_number=port_data["port"],
                protocol=port_data.get("protocol", "tcp"),
                state=port_data.get("state", "open"),
                service_name=port_data.get("service"),
                service_version=port_data.get("version"),
                service_product=port_data.get("product"),
                extra_info=port_data.get("extra_info"),
            ))
    await db.flush()
    return device


async def _clear_device_findings(db, device_id, finding_types=None) -> None:
    """Delete a device's findings; when finding_types is given, only those types."""
    stmt = sa_delete(Finding).where(Finding.device_id == device_id)
    if finding_types is not None:
        stmt = stmt.where(Finding.finding_type.in_(finding_types))
    await db.execute(stmt)
    await db.flush()


async def _create_findings_from_host(db, scan, device, host_data: dict) -> int:
    count = 0
    for f in host_data.get("findings", []):
        db.add(Finding(
            organization_id=scan.organization_id,
            scan_id=scan.id,
            device_id=device.id,
            finding_type=f["type"],
            severity=f["severity"],
            status=FindingStatus.OPEN,
            title=f["title"],
            description=f["description"],
            raw_data=f.get("raw_data", {}),
            cve_id=f.get("cve_id"),
            cvss_score=f.get("cvss_score"),
        ))
        count += 1
    await db.flush()
    return count


def _calculate_risk_score(findings: list) -> float:
    weights = {"critical": 40, "high": 20, "medium": 10, "low": 3, "info": 0}
    return min(100.0, float(sum(weights.get(str(f.get("severity", "info")).lower(), 0) for f in findings)))


@celery_app.task(name="process_agent_results")
def process_agent_results(scan_id: str, result_type: str, results: dict):
    asyncio.run(_process_agent_results_async(scan_id, result_type, results))


# Finding types owned by agent scans. An agent report replaces only the types it actually
# covers, so it can never wipe network-scan findings (open ports, CVEs) for the device.
AGENT_VIRUS_TYPES = ("virus", "suspicious_process")
AGENT_AUDIT_TYPES = ("firewall_disabled",)


async def _process_agent_results_async(scan_id: str, result_type: str, results: dict):
    async with AsyncSessionLocal() as db:
        scan = (await db.execute(select(Scan).where(Scan.id == _uuid(scan_id)))).scalar_one_or_none()
        if not scan or scan.status != ScanStatus.RUNNING or not scan.device_id:
            return  # unknown, already finished, or not an agent job

        try:
            device = (await db.execute(select(Device).where(
                Device.id == scan.device_id,
                Device.organization_id == scan.organization_id,
            ))).scalar_one_or_none()
            if not device:
                raise ValueError("device no longer exists")

            created = 0
            sections = 0          # report sections that were actually produced by a real scan
            problem = None        # why a section could not be used

            # Virus scan results (top-level, or nested under "virus" for full-device scans)
            virus_data = results if "infected_files" in results else results.get("virus", {})
            if isinstance(virus_data, dict) and virus_data.get("error"):
                # The agent could not scan (e.g. ClamAV missing). That is NOT a clean result:
                # keep existing findings and surface the problem instead.
                problem = str(virus_data["error"])[:200]
            elif isinstance(virus_data, dict) and "infected_files" in virus_data:
                sections += 1
                await _clear_device_findings(db, device.id, AGENT_VIRUS_TYPES)
                for f_data in VirusScanService().parse_agent_results(virus_data):
                    db.add(Finding(
                        organization_id=scan.organization_id, scan_id=scan.id, device_id=device.id,
                        finding_type=f_data["type"], severity=f_data["severity"], status=FindingStatus.OPEN,
                        title=f_data["title"][:500], description=f_data["description"],
                        virus_name=f_data.get("virus_name"), file_path=f_data.get("file_path"),
                        file_hash=f_data.get("file_hash"), raw_data=f_data.get("raw_data", {}),
                    ))
                    created += 1

            # System audit results
            audit = results.get("results", results)
            fw = audit.get("firewall") if isinstance(audit, dict) else None
            if isinstance(fw, dict) and fw.get("enabled") is not None:
                sections += 1
                await _clear_device_findings(db, device.id, AGENT_AUDIT_TYPES)
                if fw.get("enabled") is False:
                    db.add(Finding(
                        organization_id=scan.organization_id, scan_id=scan.id, device_id=device.id,
                        finding_type="firewall_disabled", severity=Severity.HIGH, status=FindingStatus.OPEN,
                        title="Local firewall is disabled",
                        description=(
                            f"Firewall inactive on {device.hostname or device.ip_address}. "
                            f"Method: {fw.get('method')}. {str(fw.get('details', ''))[:200]}"
                        ),
                        raw_data=fw,
                    ))
                    created += 1

            scan.completed_at = datetime.now(timezone.utc)
            if sections == 0:
                scan.status = ScanStatus.FAILED
                scan.error_message = problem or "The agent's report contained no usable results."
            else:
                scan.findings_count = created
                scan.hosts_discovered = 1
                scan.status = ScanStatus.COMPLETED
                if problem:
                    scan.error_message = f"Partially completed: {problem}"
            await db.commit()
            log.info("agent_results_processed", scan_id=scan_id, findings=created)
        except Exception as e:
            await db.rollback()
            log.error("agent_results_failed", scan_id=scan_id, error=type(e).__name__)
            scan = (await db.execute(select(Scan).where(Scan.id == _uuid(scan_id)))).scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = "Could not process the agent's results."
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()


@celery_app.task(name="generate_ai_remediation")
def generate_ai_remediation(finding_id: str, org_id: str):
    asyncio.run(_generate_ai_remediation_async(finding_id, org_id))


async def _generate_ai_remediation_async(finding_id: str, org_id: str):
    async with AsyncSessionLocal() as db:
        fr = await db.execute(select(Finding).where(Finding.id == _uuid(finding_id)).options(selectinload(Finding.device)))
        finding = fr.scalar_one_or_none()
        if not finding or not finding.device:
            return
        or_ = await db.execute(select(Organization).where(Organization.id == _uuid(org_id)))
        org = or_.scalar_one_or_none()
        if not org:
            return
        api_key = decrypt(org.ai_api_key_encrypted) if org.ai_api_key_encrypted else None
        try:
            service = AIService(
                provider=org.ai_provider, api_key=api_key,
                model=org.ai_model, ollama_url=org.ai_ollama_url or "http://ollama:11434",
            )
            finding.ai_remediation = await service.generate_remediation(finding, finding.device)
            finding.ai_generated_at = datetime.now(timezone.utc)
            finding.ai_provider_used = org.ai_provider
            await db.commit()
            log.info("ai_remediation_generated", finding_id=finding_id)
        except Exception as e:
            log.error("ai_remediation_failed", finding_id=finding_id, error=str(e))
