#!/usr/bin/env python3
"""
NetAudit Local Agent — Cross-platform (Windows, macOS, Linux)
Runs on employee machines. Performs virus scanning and device scans,
reports findings securely to the NetAudit dashboard.

Install (Windows):  powershell -ExecutionPolicy Bypass -File install_windows.ps1 -DashboardUrl https://... -AgentToken ...
Install (Linux):    python3 agent.py configure --url https://... --token ... && python3 agent.py install
Install (macOS):    python3 agent.py configure --url https://... --token ... && python3 agent.py install
Run manually:       python3 agent.py start
"""
import argparse
import asyncio
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import structlog

log = structlog.get_logger()

CONFIG_PATH = Path.home() / ".netaudit" / "agent.json"
VERSION = "1.0.0"
IS_WINDOWS = platform.system() == "Windows"
IS_MACOS   = platform.system() == "Darwin"
IS_LINUX   = platform.system() == "Linux"

# ClamAV install locations on Windows (checked when not in PATH)
_WINDOWS_CLAMAV_DIRS = [
    Path("C:/Program Files/ClamAV"),
    Path("C:/Program Files (x86)/ClamAV"),
    Path("C:/ClamAV"),
]


# ─── Configuration ────────────────────────────────────────────────

def load_config() -> dict:
    if not CONFIG_PATH.exists():
        print("Agent not configured. Run: python agent.py configure --url https://your-dashboard --token YOUR_TOKEN")
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return json.load(f)


def save_config(config: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
    # chmod not supported on Windows
    if not IS_WINDOWS:
        CONFIG_PATH.chmod(0o600)


# ─── System Info ──────────────────────────────────────────────────

def get_system_info() -> dict:
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "agent_version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def get_local_ip() -> str:
    """Best-effort local IP detection."""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


# ─── Virus Scanning (ClamAV) ──────────────────────────────────────

def _find_exe(name: str, windows_dirs: list) -> Optional[str]:
    """Find an executable in PATH first, then Windows-specific directories."""
    if shutil.which(name):
        return name
    if IS_WINDOWS:
        win_name = name + ".exe"
        for d in windows_dirs:
            candidate = Path(d) / win_name
            if candidate.exists():
                return str(candidate)
    return None


class VirusScanner:

    def __init__(self):
        self.clamscan_exe  = _find_exe("clamscan",  _WINDOWS_CLAMAV_DIRS)
        self.freshclam_exe = _find_exe("freshclam", _WINDOWS_CLAMAV_DIRS)
        self.clamav_available = self.clamscan_exe is not None

    def update_signatures(self) -> bool:
        if not self.freshclam_exe:
            return False
        try:
            log.info("updating_clamav_signatures")
            result = subprocess.run(
                [self.freshclam_exe], capture_output=True, text=True, timeout=300
            )
            return result.returncode == 0
        except Exception as e:
            log.warning("freshclam_update_failed", error=str(e))
            return False

    def scan_path(self, scan_path: str, quick: bool = False) -> dict:
        if not self.clamav_available:
            return {"error": "ClamAV not installed", "infected_files": []}

        targets = self._get_quick_scan_targets() if quick else [scan_path]

        infected_files = []
        scan_stats = {"scanned": 0, "infected": 0, "errors": 0}

        for target in targets:
            if not Path(target).exists():
                continue
            log.info("scanning_path", path=target)
            try:
                result = subprocess.run(
                    [
                        self.clamscan_exe,
                        "--recursive",
                        "--infected",
                        "--no-summary",
                        "--stdout",
                        target,
                    ],
                    capture_output=True, text=True,
                    timeout=3600,
                )
                for line in result.stdout.splitlines():
                    if "FOUND" in line:
                        parts = line.rsplit(":", 1)
                        if len(parts) == 2:
                            file_path = parts[0].strip()
                            virus_name = parts[1].replace("FOUND", "").strip()
                            infected_files.append({
                                "path": file_path,
                                "virus_name": virus_name,
                                "sha256": self._hash_file(file_path),
                                "action": "flagged",
                                "detected_at": datetime.now(timezone.utc).isoformat(),
                            })
                            scan_stats["infected"] += 1
                scan_stats["scanned"] += 1
            except subprocess.TimeoutExpired:
                log.warning("scan_timeout", path=target)
            except Exception as e:
                log.error("scan_error", path=target, error=str(e))
                scan_stats["errors"] += 1

        return {
            "infected_files": infected_files,
            "stats": scan_stats,
            "scan_paths": targets,
            "clamav_version": self._get_clamav_version(),
        }

    def _get_quick_scan_targets(self) -> list:
        home = Path.home()
        seen = set()
        targets = []

        if IS_WINDOWS:
            candidates = [
                home / "Downloads",
                home / "Desktop",
                home / "Documents",
                home / "AppData" / "Local" / "Temp",
                home / "AppData" / "Roaming",
                Path(os.environ.get("TEMP", str(home / "AppData" / "Local" / "Temp"))),
            ]
        else:
            candidates = [
                home / "Downloads",
                home / "Desktop",
                home / "Documents",
                Path("/tmp"),
                Path(os.environ.get("TEMP", "/tmp")),
            ]

        for p in candidates:
            resolved = str(p.resolve()) if p.exists() else str(p)
            if p.exists() and resolved not in seen:
                seen.add(resolved)
                targets.append(str(p))

        return targets or [str(home)]

    def _hash_file(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _get_clamav_version(self) -> str:
        if not self.clamscan_exe:
            return "not installed"
        try:
            result = subprocess.run(
                [self.clamscan_exe, "--version"], capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip().split("\n")[0]
        except Exception:
            return "unknown"


# ─── System Audit ─────────────────────────────────────────────────

class SystemAuditor:

    def get_open_ports(self) -> list:
        ports = []
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ["netstat", "-ano"], capture_output=True, text=True
                )
            else:
                result = subprocess.run(
                    ["ss", "-tlnp"], capture_output=True, text=True
                )
            for line in result.stdout.splitlines():
                if "LISTEN" in line or "0.0.0.0" in line:
                    ports.append({"raw": line.strip()})
        except Exception as e:
            log.warning("port_audit_failed", error=str(e))
        return ports

    def get_running_processes(self) -> list:
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ["tasklist", "/fo", "csv", "/v"], capture_output=True, text=True
                )
            else:
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
            lines = result.stdout.strip().splitlines()
            return [{"raw": line} for line in lines[:100]]
        except Exception:
            return []

    def get_installed_software(self) -> list:
        software = []
        try:
            if IS_WINDOWS:
                software = self._get_installed_software_windows()
            elif IS_LINUX:
                result = subprocess.run(
                    ["dpkg", "--get-selections"], capture_output=True, text=True
                )
                for line in result.stdout.splitlines()[:200]:
                    parts = line.split()
                    if parts:
                        software.append({"name": parts[0], "status": parts[-1] if len(parts) > 1 else ""})
            elif IS_MACOS:
                result = subprocess.run(
                    ["ls", "/Applications"], capture_output=True, text=True
                )
                for line in result.stdout.splitlines():
                    if line.endswith(".app"):
                        software.append({"name": line[:-4]})
        except Exception as e:
            log.warning("software_audit_failed", error=str(e))
        return software

    def _get_installed_software_windows(self) -> list:
        """Read installed programs from the Windows registry."""
        software = []
        seen = set()
        reg_keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ]
        for key in reg_keys:
            try:
                result = subprocess.run(
                    ["reg", "query", key, "/s", "/v", "DisplayName"],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if "DisplayName" in line and "REG_SZ" in line:
                        parts = line.split("REG_SZ", 1)
                        if len(parts) == 2:
                            name = parts[1].strip()
                            if name and name not in seen:
                                seen.add(name)
                                software.append({"name": name})
            except Exception:
                continue
        return software[:300]  # cap to avoid huge payloads

    def check_firewall_status(self) -> dict:
        status = {"enabled": None, "details": ""}
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"],
                    capture_output=True, text=True, timeout=10
                )
                output = result.stdout
                # Each profile shows "State   ON" or "State   OFF"
                states = [
                    line.strip().split()[-1].upper()
                    for line in output.splitlines()
                    if line.strip().lower().startswith("state")
                ]
                status["enabled"] = bool(states) and all(s == "ON" for s in states)
                status["details"] = output.strip()
            elif IS_LINUX:
                result = subprocess.run(
                    ["ufw", "status"], capture_output=True, text=True
                )
                status["enabled"] = "active" in result.stdout.lower()
                status["details"] = result.stdout.strip()
            elif IS_MACOS:
                result = subprocess.run(
                    ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                    capture_output=True, text=True
                )
                status["enabled"] = "enabled" in result.stdout.lower()
                status["details"] = result.stdout.strip()
        except Exception:
            status["details"] = "Could not determine firewall status"
        return status


# ─── Agent Main Loop ──────────────────────────────────────────────

class NetAuditAgent:

    def __init__(self, config: dict):
        self.config = config
        self.base_url = _require_secure_url(config["dashboard_url"])
        self.token = config["agent_token"]
        self.virus_scanner = VirusScanner()
        self.system_auditor = SystemAuditor()
        self._tasks: set = set()
        self._running_jobs: set = set()
        self.headers = {
            "X-Agent-Token": self.token,
            "X-Agent-Version": VERSION,
            "Content-Type": "application/json",
        }

    async def checkin(self) -> Optional[dict]:
        payload = {
            "system_info": get_system_info(),
            "local_ip": get_local_ip(),
        }
        try:
            async with httpx.AsyncClient(verify=True, timeout=30) as client:
                response = await client.post(
                    f"{self.base_url}/api/agent/checkin",
                    json=payload,
                    headers=self.headers,
                )
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 401:
                    log.error("agent_auth_failed", detail="Invalid token")
                    sys.exit(1)
        except httpx.ConnectError:
            log.warning("dashboard_unreachable", url=self.base_url)
        except Exception as e:
            log.error("checkin_failed", error=str(e))
        return None

    async def _run_job(self, job: dict):
        try:
            await self.execute_job(job)
        finally:
            self._running_jobs.discard(job["id"])

    async def execute_job(self, job: dict):
        job_id = job["id"]
        job_type = job["type"]
        log.info("executing_job", job_id=job_id, type=job_type)
        try:
            if job_type == "virus_scan":
                results = await self._run_virus_scan(job)
            elif job_type == "system_audit":
                results = await self._run_system_audit(job)
            elif job_type == "full_device":
                # Combined report: audit sections at the top level plus the virus scan under "virus"
                audit = await self._run_system_audit(job)
                virus = await self._run_virus_scan(job)
                results = {
                    "type": "full_device",
                    "results": {**audit["results"], "virus": virus["results"]},
                }
            else:
                log.warning("unknown_job_type", type=job_type)
                return
            await self._upload_results(job_id, results)
        except Exception as e:
            log.error("job_failed", job_id=job_id, error=str(e))
            await self._report_job_error(job_id, f"Agent error: {type(e).__name__}")

    async def _run_virus_scan(self, job: dict) -> dict:
        quick = job.get("options", {}).get("quick", True)
        scan_path = job.get("options", {}).get("path", str(Path.home()))
        self.virus_scanner.update_signatures()
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None, self.virus_scanner.scan_path, scan_path, quick
        )
        return {"type": "virus_scan", "results": results}

    async def _run_system_audit(self, job: dict) -> dict:
        return {
            "type": "system_audit",
            "results": {
                "open_ports": self.system_auditor.get_open_ports(),
                "processes": self.system_auditor.get_running_processes(),
                "software": self.system_auditor.get_installed_software(),
                "firewall": self.system_auditor.check_firewall_status(),
                "system_info": get_system_info(),
            }
        }

    async def _upload_results(self, job_id: str, results: dict):
        async with httpx.AsyncClient(verify=True, timeout=60) as client:
            response = await client.post(
                f"{self.base_url}/api/agent/results/{job_id}",
                json=results,
                headers=self.headers,
            )
            if response.status_code == 200:
                log.info("results_uploaded", job_id=job_id)
            else:
                log.error("upload_failed", job_id=job_id, status=response.status_code)

    async def _report_job_error(self, job_id: str, error: str):
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                f"{self.base_url}/api/agent/results/{job_id}/error",
                json={"error": error},
                headers=self.headers,
            )

    async def run(self):
        log.info("agent_started", version=VERSION, dashboard=self.base_url,
                 os=platform.system(), clamav=self.virus_scanner.clamav_available)
        while True:
            checkin_data = await self.checkin()
            if checkin_data:
                for job in checkin_data.get("pending_jobs", []):
                    if job["id"] in self._running_jobs:
                        continue
                    self._running_jobs.add(job["id"])
                    task = asyncio.create_task(self._run_job(job))
                    self._tasks.add(task)
                    task.add_done_callback(self._tasks.discard)
            await asyncio.sleep(30)


# ─── CLI ──────────────────────────────────────────────────────────

def _require_secure_url(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        print("Refusing to configure: the dashboard URL must use https:// (the agent token is sent with every request).")
        sys.exit(1)
    return url.rstrip("/")


def cmd_configure(args):
    args.url = _require_secure_url(args.url)
    config = {
        "dashboard_url": args.url,
        "agent_token": args.token,
        "configured_at": datetime.now(timezone.utc).isoformat(),
    }
    save_config(config)
    print(f"Agent configured. Dashboard: {args.url}")
    print(f"Config saved to: {CONFIG_PATH}")


def cmd_start(args):
    config = load_config()
    agent = NetAuditAgent(config)
    asyncio.run(agent.run())


def cmd_install(args):
    """Register agent to start automatically at logon/boot."""
    agent_script = str(Path(__file__).resolve())
    python_exe   = sys.executable

    if IS_WINDOWS:
        _install_windows(python_exe, agent_script)
    elif IS_LINUX:
        _install_linux(python_exe, agent_script)
    elif IS_MACOS:
        _install_macos(python_exe, agent_script)
    else:
        print("Unsupported platform. Start manually: python agent.py start")


def _install_windows(python_exe: str, agent_script: str):
    task_name = "NetAuditAgent"
    cmd = f'"{python_exe}" "{agent_script}" start'
    result = subprocess.run(
        [
            "schtasks", "/create",
            "/tn", task_name,
            "/tr", cmd,
            "/sc", "ONLOGON",
            "/rl", "HIGHEST",
            "/f",
        ],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print(f"Installed as Windows Scheduled Task: {task_name}")
        print("Agent will start automatically at next logon.")
        # Start it now too
        subprocess.run(["schtasks", "/run", "/tn", task_name], capture_output=True)
        print("Agent started.")
    else:
        print(f"ERROR: {result.stderr.strip()}")
        print("Try running this command as Administrator.")


def _install_linux(python_exe: str, agent_script: str):
    service_src = Path(__file__).parent / "netaudit-agent.service"
    service_dst = Path("/etc/systemd/system/netaudit-agent.service")
    if not service_src.exists():
        print(f"Service file not found: {service_src}")
        return
    content = service_src.read_text()
    content = content.replace("/usr/bin/python3", python_exe)
    content = content.replace("/opt/netaudit/agent.py", agent_script)
    try:
        service_dst.write_text(content)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", "netaudit-agent"], check=True)
        print("Agent installed and started via systemd.")
        print("Check status: systemctl status netaudit-agent")
    except PermissionError:
        print("ERROR: Run as root (sudo python3 agent.py install)")
    except subprocess.CalledProcessError as e:
        print(f"ERROR: {e}")


def _install_macos(python_exe: str, agent_script: str):
    plist_src = Path(__file__).parent / "com.netaudit.agent.plist"
    plist_dst = Path.home() / "Library" / "LaunchAgents" / "com.netaudit.agent.plist"
    if not plist_src.exists():
        print(f"Plist file not found: {plist_src}")
        return
    content = plist_src.read_text()
    content = content.replace("/usr/bin/python3", python_exe)
    content = content.replace("/opt/netaudit/agent.py", agent_script)
    plist_dst.parent.mkdir(parents=True, exist_ok=True)
    plist_dst.write_text(content)
    result = subprocess.run(
        ["launchctl", "load", "-w", str(plist_dst)],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print(f"Agent installed as LaunchAgent: {plist_dst}")
        print("Agent will start automatically at login.")
    else:
        print(f"ERROR: {result.stderr.strip()}")


def cmd_uninstall(args):
    """Remove the agent from auto-start."""
    if IS_WINDOWS:
        task_name = "NetAuditAgent"
        subprocess.run(["schtasks", "/end",    "/tn", task_name], capture_output=True)
        subprocess.run(["schtasks", "/delete", "/tn", task_name, "/f"], capture_output=True)
        print(f"Removed scheduled task: {task_name}")
    elif IS_LINUX:
        subprocess.run(["systemctl", "disable", "--now", "netaudit-agent"], capture_output=True)
        Path("/etc/systemd/system/netaudit-agent.service").unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        print("Removed systemd service.")
    elif IS_MACOS:
        plist_dst = Path.home() / "Library" / "LaunchAgents" / "com.netaudit.agent.plist"
        subprocess.run(["launchctl", "unload", str(plist_dst)], capture_output=True)
        plist_dst.unlink(missing_ok=True)
        print("Removed LaunchAgent.")


def cmd_scan(args):
    """Manual one-off virus scan for testing."""
    scanner = VirusScanner()
    if not scanner.clamav_available:
        print("ClamAV not found. Install it first:")
        if IS_WINDOWS:
            print("  winget install ClamAV.ClamAV")
            print("  or download from https://www.clamav.net/downloads")
        elif IS_MACOS:
            print("  brew install clamav")
        else:
            print("  sudo apt install clamav clamav-freshclam")
        sys.exit(1)
    print(f"Running {'quick' if args.quick else 'full'} virus scan...")
    results = scanner.scan_path(args.path or str(Path.home()), quick=args.quick)
    print(json.dumps(results, indent=2))


def cmd_status(args):
    """Show agent status and what's available on this machine."""
    scanner = VirusScanner()
    print(f"Platform  : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python    : {sys.version.split()[0]}")
    print(f"ClamAV    : {scanner._get_clamav_version() if scanner.clamav_available else 'NOT FOUND'}")
    if scanner.clamscan_exe:
        print(f"  clamscan : {scanner.clamscan_exe}")
    if scanner.freshclam_exe:
        print(f"  freshclam: {scanner.freshclam_exe}")
    print(f"Config    : {'EXISTS' if CONFIG_PATH.exists() else 'NOT CONFIGURED'} ({CONFIG_PATH})")
    if CONFIG_PATH.exists():
        cfg = load_config()
        print(f"Dashboard : {cfg.get('dashboard_url')}")

    if IS_WINDOWS:
        r = subprocess.run(["schtasks", "/query", "/tn", "NetAuditAgent"],
                           capture_output=True, text=True)
        print(f"Auto-start: {'INSTALLED' if r.returncode == 0 else 'not installed'} (scheduled task)")
    elif IS_LINUX:
        r = subprocess.run(["systemctl", "is-active", "netaudit-agent"],
                           capture_output=True, text=True)
        print(f"Service   : {r.stdout.strip()}")
    elif IS_MACOS:
        plist = Path.home() / "Library" / "LaunchAgents" / "com.netaudit.agent.plist"
        print(f"LaunchAgent: {'INSTALLED' if plist.exists() else 'not installed'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetAudit Local Agent")
    subparsers = parser.add_subparsers(dest="command")

    p_configure = subparsers.add_parser("configure", help="Set up agent connection")
    p_configure.add_argument("--url",   required=True, help="Dashboard URL")
    p_configure.add_argument("--token", required=True, help="Agent token from dashboard")
    p_configure.set_defaults(func=cmd_configure)

    p_start = subparsers.add_parser("start", help="Start agent daemon")
    p_start.set_defaults(func=cmd_start)

    p_install = subparsers.add_parser("install", help="Register agent to start at logon/boot")
    p_install.set_defaults(func=cmd_install)

    p_uninstall = subparsers.add_parser("uninstall", help="Remove agent from auto-start")
    p_uninstall.set_defaults(func=cmd_uninstall)

    p_scan = subparsers.add_parser("scan", help="Run a manual virus scan")
    p_scan.add_argument("--path",  help="Path to scan (default: home dir)")
    p_scan.add_argument("--quick", action="store_true", help="Quick scan of common locations")
    p_scan.set_defaults(func=cmd_scan)

    p_status = subparsers.add_parser("status", help="Show agent status")
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
