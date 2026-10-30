"""
Scan execution service.
Runs Nmap, parses XML output, detects findings, stores results.
"""
import asyncio
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import nmap
import structlog

from app.models.models import (
    Device, Port, Scan, Finding, ScanStatus, Severity, FindingStatus
)
from app.core.config import settings

log = structlog.get_logger()


def infer_device_type(hostname: str | None, nmap_type: str | None) -> str:
    """
    Return a normalised device_type string.
    Uses Nmap OS class when meaningful; falls back to hostname pattern matching
    (critical for UniFi gear that Nmap cannot fingerprint).
    """
    import re
    skip = {"unknown", "general purpose", ""}
    if nmap_type and nmap_type.lower() not in skip:
        t = nmap_type.lower()
        if t in ("router", "broadband router", "firewall"):
            return "gateway"
        if t in ("switch", "hub"):
            return "switch"
        if t in ("wap", "wireless access point"):
            return "access_point"
        if t in ("printer", "print server"):
            return "printer"
        if t not in ("general purpose", "specialized"):
            return t

    if not hostname:
        return "unknown"

    h = hostname.lower()

    # UniFi switches: USW-* family, legacy US-## models (not USG/UXG gateways)
    if re.match(r"^usw-", h) or re.match(r"^us-\d", h):
        return "switch"
    # UniFi access points: U6-*, U7-*, UAP-*
    if re.match(r"^u[67]-", h) or re.match(r"^uap-", h):
        return "access_point"
    # UniFi gateways / controllers: UDM, USG, UXG, UGW, or hostname == "unifi"
    if h == "unifi" or re.match(r"^(udm|usg|uxg|ugw)", h):
        return "gateway"

    # Generic patterns
    if any(x in h for x in ("router", "gateway", "firewall", "pfsense", "opnsense", "fw-", "-fw")):
        return "gateway"
    if any(x in h for x in ("switch", "-sw-", "sw-", "-sw")):
        return "switch"
    if any(x in h for x in ("wifi", "wireless", "-ap-", "-ap", "ap-")):
        return "access_point"
    if re.match(r"^(desktop|laptop|workstation|pc)-", h) or "desktop-" in h:
        return "workstation"
    if any(x in h for x in ("printer", "print", "ricoh", "xerox", "canon-", "hp-laser")):
        return "printer"
    if any(x in h for x in ("server", "srv", "-vm", "vm-", "gitlab", "proxmox",
                             "esxi", "vcenter", "docker", "k8s", "nas-", "-nas")):
        return "server"

    return "unknown"


# ─── Ports that should trigger findings ───────────────────────────
SENSITIVE_PORTS = {
    21: ("FTP - unencrypted file transfer", Severity.HIGH),
    22: ("SSH exposed", Severity.MEDIUM),
    23: ("Telnet - plaintext remote access", Severity.CRITICAL),
    25: ("SMTP relay potentially open", Severity.MEDIUM),
    445: ("SMB - check for EternalBlue/SMBv1", Severity.HIGH),
    1433: ("MSSQL exposed to network", Severity.HIGH),
    3306: ("MySQL exposed to network", Severity.HIGH),
    3389: ("RDP exposed to network", Severity.HIGH),
    5432: ("PostgreSQL exposed to network", Severity.HIGH),
    5900: ("VNC - remote desktop exposed", Severity.HIGH),
    6379: ("Redis exposed without auth", Severity.CRITICAL),
    27017: ("MongoDB exposed to network", Severity.HIGH),
    8080: ("HTTP admin interface exposed", Severity.MEDIUM),
    8443: ("HTTPS admin interface exposed", Severity.MEDIUM),
}

OUTDATED_VERSIONS = [
    ("openssh", "6.", Severity.HIGH, "OpenSSH version is outdated with known vulnerabilities"),
    ("apache", "2.2.", Severity.HIGH, "Apache 2.2 is end-of-life"),
    ("nginx", "1.1", Severity.MEDIUM, "Nginx version may be outdated"),
    ("vsftpd", "2.", Severity.HIGH, "vsftpd 2.x has known critical vulnerabilities"),
    ("samba", "3.", Severity.CRITICAL, "Samba 3.x is end-of-life with critical CVEs"),
]


class NmapScanService:

    def __init__(self, output_base_path: str = "/app/scan_results"):
        self.output_path = Path(output_base_path)
        self.output_path.mkdir(parents=True, exist_ok=True)

    async def run_scan(
        self,
        scan: Scan,
        scan_type: str,
        target: str,
    ) -> dict:
        """Execute Nmap scan in a thread pool (blocking operation)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._run_nmap_sync, scan, scan_type, target
        )

    def _run_nmap_sync(self, scan: Scan, scan_type: str, target: str) -> dict:
        nm = nmap.PortScanner()
        output_file = self.output_path / f"scan_{scan.id}.xml"

        # Build Nmap arguments based on scan type
        args = self._build_nmap_args(scan_type)

        log.info("nmap_scan_started", target=target, args=args, scan_id=str(scan.id))

        try:
            nm.scan(hosts=target, arguments=args, timeout=settings.SCAN_TIMEOUT_SECONDS)
        except nmap.PortScannerError as e:
            log.error("nmap_scan_failed", error=str(e), scan_id=str(scan.id))
            raise

        return {
            "scan_info": nm.scaninfo(),
            "hosts": self._parse_hosts(nm),
            "raw_output_path": str(output_file),
        }

    def _build_nmap_args(self, scan_type: str) -> str:
        args = {
            "network_discovery": "-sn",
            "port_scan":         "-sS -sV -O --top-ports 1000",
            "vulnerability":     "-sS -sV -O --script vuln",
            "compliance":        "-sS -sV -O --script auth,default",
            "full_network":      "-sS -sV -O --script vuln,auth --top-ports 2000",
            "full_device":       "-sS -sV -O -p- --script vuln",
        }
        return args.get(scan_type, args["port_scan"])

    def _parse_hosts(self, nm: nmap.PortScanner) -> list:
        hosts = []
        for host in nm.all_hosts():
            host_data = {
                "ip": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "os": self._extract_os(nm[host]),
                "ports": [],
                "findings": [],
            }

            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    port_info = nm[host][proto][port]
                    port_data = {
                        "port": port,
                        "protocol": proto,
                        "state": port_info.get("state", ""),
                        "service": port_info.get("name", ""),
                        "version": port_info.get("version", ""),
                        "product": port_info.get("product", ""),
                        "extra_info": port_info.get("extrainfo", ""),
                    }
                    host_data["ports"].append(port_data)

                    # Generate findings for this port
                    findings = self._check_port_findings(port, port_data)
                    host_data["findings"].extend(findings)

            hosts.append(host_data)
        return hosts

    def _extract_os(self, host_data) -> dict:
        try:
            matches = host_data.get("osmatch", [])
            if matches:
                best = matches[0]
                return {
                    "name": best.get("name", "Unknown"),
                    "accuracy": int(best.get("accuracy", 0)),
                    "type": best.get("osclass", [{}])[0].get("type", "Unknown"),
                }
        except (IndexError, KeyError):
            pass
        return {"name": "Unknown", "accuracy": 0, "type": "Unknown"}

    def _check_port_findings(self, port_number: int, port_data: dict) -> list:
        findings = []

        # Sensitive port check
        if port_number in SENSITIVE_PORTS and port_data["state"] == "open":
            desc, severity = SENSITIVE_PORTS[port_number]
            findings.append({
                "type": "open_port",
                "severity": severity,
                "title": f"Port {port_number}/{port_data['protocol']} open: {port_data['service']}",
                "description": desc,
                "raw_data": port_data,
            })

        # Outdated version check
        service_str = f"{port_data.get('product', '')} {port_data.get('version', '')}".lower()
        for service_key, version_prefix, severity, description in OUTDATED_VERSIONS:
            if service_key in service_str and version_prefix in service_str:
                findings.append({
                    "type": "outdated_service",
                    "severity": severity,
                    "title": f"Outdated {service_key} version detected: {port_data.get('version')}",
                    "description": description,
                    "raw_data": port_data,
                })

        return findings


class VirusScanService:
    """
    Receives virus scan results from the local agent.
    The actual scanning happens on-device via ClamAV in the agent.
    This service processes and stores the results.
    """

    def parse_agent_results(self, raw_results: dict) -> list:
        """Parse structured virus scan results uploaded by the agent."""
        findings = []

        for infected_file in raw_results.get("infected_files", []):
            severity = self._assess_severity(infected_file.get("virus_name", ""))
            findings.append({
                "type": "virus",
                "severity": severity,
                "title": f"Malware detected: {infected_file.get('virus_name', 'Unknown')}",
                "description": (
                    f"ClamAV detected malware in file: {infected_file.get('path')}. "
                    f"Threat: {infected_file.get('virus_name')}. "
                    f"Action taken: {infected_file.get('action', 'flagged')}."
                ),
                "virus_name": infected_file.get("virus_name"),
                "file_path": infected_file.get("path"),
                "file_hash": infected_file.get("sha256"),
                "raw_data": infected_file,
            })

        for suspicious in raw_results.get("suspicious_processes", []):
            findings.append({
                "type": "suspicious_process",
                "severity": Severity.HIGH,
                "title": f"Suspicious process: {suspicious.get('name')}",
                "description": (
                    f"Process {suspicious.get('name')} (PID {suspicious.get('pid')}) "
                    f"shows characteristics of malicious activity: {suspicious.get('reason')}"
                ),
                "raw_data": suspicious,
            })

        return findings

    def _assess_severity(self, virus_name: str) -> Severity:
        virus_lower = virus_name.lower()
        if any(x in virus_lower for x in ["trojan", "ransomware", "rootkit", "backdoor", "rat."]):
            return Severity.CRITICAL
        if any(x in virus_lower for x in ["worm", "spyware", "keylogger", "banker"]):
            return Severity.HIGH
        if any(x in virus_lower for x in ["adware", "pup.", "potentially"]):
            return Severity.LOW
        return Severity.MEDIUM
