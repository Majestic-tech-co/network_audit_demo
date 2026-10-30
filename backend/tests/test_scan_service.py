"""
Unit tests for NmapScanService and VirusScanService.
No DB, no network — all pure logic.
"""
import pytest

from app.services.scanner.scan_service import (
    NmapScanService,
    VirusScanService,
    SENSITIVE_PORTS,
    OUTDATED_VERSIONS,
)
from app.models.models import Severity


nmap_svc = NmapScanService.__new__(NmapScanService)  # bypass __init__ (skips mkdir)
virus_svc = VirusScanService()


# ── _build_nmap_args ───────────────────────────────────────────────

@pytest.mark.parametrize("scan_type,expected_fragment", [
    ("network_discovery", "-sn"),
    ("port_scan", "--top-ports 1000"),
    ("vulnerability", "--script vuln"),
    ("compliance", "--script auth,default"),
    ("full_network", "--top-ports 2000"),
    ("full_device", "-p-"),
])
def test_build_nmap_args_contains_expected_flags(scan_type, expected_fragment):
    args = nmap_svc._build_nmap_args(scan_type)
    assert expected_fragment in args


def test_build_nmap_args_unknown_type_defaults_to_port_scan():
    args = nmap_svc._build_nmap_args("nonexistent_type")
    assert "--top-ports 1000" in args


# ── _check_port_findings ───────────────────────────────────────────

def _port(port_number, service="unknown", version="", product="", state="open"):
    return {
        "port": port_number,
        "protocol": "tcp",
        "state": state,
        "service": service,
        "version": version,
        "product": product,
        "extra_info": "",
    }


@pytest.mark.parametrize("port_number,expected_severity", [
    (23,   Severity.CRITICAL),   # Telnet
    (6379, Severity.CRITICAL),   # Redis
    (21,   Severity.HIGH),       # FTP
    (3389, Severity.HIGH),       # RDP
    (22,   Severity.MEDIUM),     # SSH
])
def test_sensitive_open_port_generates_finding(port_number, expected_severity):
    findings = nmap_svc._check_port_findings(port_number, _port(port_number))
    assert len(findings) >= 1
    severities = {f["severity"] for f in findings}
    assert expected_severity in severities


def test_sensitive_port_closed_generates_no_finding():
    findings = nmap_svc._check_port_findings(21, _port(21, state="closed"))
    assert findings == []


def test_non_sensitive_open_port_generates_no_finding():
    findings = nmap_svc._check_port_findings(80, _port(80, service="http"))
    assert findings == []


@pytest.mark.parametrize("product,version,expected_severity", [
    ("OpenSSH", "6.7p1", Severity.HIGH),
    ("Apache httpd", "2.2.34", Severity.HIGH),
    ("vsftpd", "2.3.4", Severity.HIGH),
    ("Samba", "3.6.25", Severity.CRITICAL),
])
def test_outdated_service_generates_finding(product, version, expected_severity):
    port_data = _port(8080, service="http", product=product, version=version)
    findings = nmap_svc._check_port_findings(8080, port_data)
    outdated = [f for f in findings if f["type"] == "outdated_service"]
    assert len(outdated) >= 1
    assert outdated[0]["severity"] == expected_severity


def test_current_openssh_version_no_outdated_finding():
    port_data = _port(22, service="ssh", product="OpenSSH", version="9.7p1")
    findings = nmap_svc._check_port_findings(22, port_data)
    outdated = [f for f in findings if f["type"] == "outdated_service"]
    assert outdated == []


def test_sensitive_port_with_outdated_service_generates_multiple_findings():
    # Port 22 is sensitive AND version is outdated → should get both findings.
    port_data = _port(22, service="ssh", product="OpenSSH", version="6.7p1")
    findings = nmap_svc._check_port_findings(22, port_data)
    types = [f["type"] for f in findings]
    assert "open_port" in types
    assert "outdated_service" in types


# ── _extract_os ────────────────────────────────────────────────────

def test_extract_os_with_match():
    host_data = {
        "osmatch": [
            {"name": "Linux 5.4", "accuracy": "95", "osclass": [{"type": "general purpose"}]}
        ]
    }
    result = nmap_svc._extract_os(host_data)
    assert result["name"] == "Linux 5.4"
    assert result["accuracy"] == 95


def test_extract_os_empty_returns_unknown():
    result = nmap_svc._extract_os({})
    assert result["name"] == "Unknown"
    assert result["accuracy"] == 0


# ── VirusScanService._assess_severity ─────────────────────────────

@pytest.mark.parametrize("virus_name,expected", [
    ("Trojan.Generic.XYZ",          Severity.CRITICAL),
    ("Win32.Ransomware.Locky",      Severity.CRITICAL),
    ("Linux.Rootkit.Umbreon",       Severity.CRITICAL),
    ("Backdoor.Agent.42",           Severity.CRITICAL),
    ("Email.Worm.Bagle",            Severity.HIGH),
    ("Spyware.AgentTesla",          Severity.HIGH),
    ("Keylogger.Generic",           Severity.HIGH),
    ("Adware.SearchSuite",          Severity.LOW),
    ("PUP.Optional.Bundler",        Severity.LOW),
    ("Potentially.Unwanted.Stuff",  Severity.LOW),
    ("Eicar-Test-Signature",        Severity.MEDIUM),
])
def test_virus_severity_classification(virus_name, expected):
    assert virus_svc._assess_severity(virus_name) == expected


# ── VirusScanService.parse_agent_results ──────────────────────────

def test_parse_infected_files():
    raw = {
        "infected_files": [
            {
                "path": "/tmp/evil.exe",
                "virus_name": "Trojan.Generic",
                "sha256": "abc123",
                "action": "quarantined",
            }
        ],
        "suspicious_processes": [],
    }
    findings = virus_svc.parse_agent_results(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "virus"
    assert f["severity"] == Severity.CRITICAL
    assert f["virus_name"] == "Trojan.Generic"
    assert f["file_path"] == "/tmp/evil.exe"
    assert f["file_hash"] == "abc123"


def test_parse_suspicious_process():
    raw = {
        "infected_files": [],
        "suspicious_processes": [
            {"name": "cryptominer", "pid": 1234, "reason": "high CPU + network"},
        ],
    }
    findings = virus_svc.parse_agent_results(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "suspicious_process"
    assert f["severity"] == Severity.HIGH
    assert "cryptominer" in f["title"]


def test_parse_empty_results():
    findings = virus_svc.parse_agent_results({"infected_files": [], "suspicious_processes": []})
    assert findings == []


def test_parse_combined_results():
    raw = {
        "infected_files": [{"path": "/x", "virus_name": "X", "sha256": "y", "action": "flagged"}],
        "suspicious_processes": [{"name": "miner", "pid": 9, "reason": "cpu"}],
    }
    findings = virus_svc.parse_agent_results(raw)
    assert len(findings) == 2
    types = {f["type"] for f in findings}
    assert types == {"virus", "suspicious_process"}
