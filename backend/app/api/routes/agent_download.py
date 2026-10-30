"""
Agent installer download route.
GET /api/agent/download/{platform}  — returns a zip with agent files + README
"""
import zipfile
from io import BytesIO
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from app.core.limiter import limiter
from app.core.auth import get_current_admin
from app.models.models import User

router = APIRouter(prefix="/api/agent", tags=["agent-download"])

AGENT_FILES_DIR = Path(__file__).parent.parent.parent.parent / "agent_files"

PLATFORM_FILES = {
    "windows": ["agent.py", "install_windows.ps1", "install_windows.bat"],
    "linux":   ["agent.py", "netaudit-agent.service"],
    "macos":   ["agent.py", "com.netaudit.agent.plist"],
}

READMES = {
    "windows": """\
NetAudit Agent — Windows Setup
================================

Requirements
------------
- Python 3.9 or newer  (https://www.python.org/downloads/)
- ClamAV for Windows   (https://www.clamav.net/downloads)
  (optional — virus scanning only)

Quick install (recommended — run as Administrator)
---------------------------------------------------
1. Open PowerShell as Administrator
2. Run:
     powershell -ExecutionPolicy Bypass -File install_windows.ps1 `
       -DashboardUrl {dashboard_url} `
       -AgentToken YOUR_TOKEN

   Add -InstallClamAV to also install ClamAV automatically via winget.

Manual install
--------------
1. Install Python dependencies:
     pip install httpx structlog

2. Configure the agent:
     python agent.py configure --url {dashboard_url} --token YOUR_TOKEN

3. Register as a Scheduled Task (auto-start at logon):
     python agent.py install

4. Check everything is working:
     python agent.py status

Tokens
------
Agent tokens are created in the NetAudit dashboard under
Users > (select user) > Agent Token.

Commands
--------
  python agent.py start      Start manually (for testing)
  python agent.py status     Show ClamAV / config / task state
  python agent.py scan       Run a quick virus scan immediately
  python agent.py uninstall  Remove from auto-start
""",

    "linux": """\
NetAudit Agent — Linux Setup
==============================

Requirements
------------
- Python 3.9+   (usually pre-installed)
- ClamAV        sudo apt install clamav clamav-freshclam
                sudo yum install clamav clamav-update   (RHEL/Rocky)

Install
-------
1. Install Python dependencies:
     pip3 install httpx structlog

2. Configure the agent:
     python3 agent.py configure --url {dashboard_url} --token YOUR_TOKEN

3. Register as a systemd service (auto-start at boot):
     sudo python3 agent.py install

4. Check status:
     python3 agent.py status
     systemctl status netaudit-agent

Notes
-----
The systemd service file (netaudit-agent.service) will be copied to
/etc/systemd/system/ and enabled. The agent runs as the current user.

Tokens
------
Agent tokens are created in the NetAudit dashboard under
Users > (select user) > Agent Token.

Commands
--------
  python3 agent.py start      Start manually (for testing)
  python3 agent.py status     Show ClamAV / config / service state
  python3 agent.py scan       Run a quick virus scan immediately
  python3 agent.py uninstall  Disable and remove systemd service
""",

    "macos": """\
NetAudit Agent — macOS Setup
==============================

Requirements
------------
- Python 3.9+   (pre-installed on macOS 12+; or via https://python.org)
- ClamAV        brew install clamav
                (Homebrew: https://brew.sh)

Install
-------
1. Install Python dependencies:
     pip3 install httpx structlog

2. Configure the agent:
     python3 agent.py configure --url {dashboard_url} --token YOUR_TOKEN

3. Register as a LaunchAgent (auto-start at login):
     python3 agent.py install

4. Check status:
     python3 agent.py status

Notes
-----
The LaunchAgent plist (com.netaudit.agent.plist) is installed to
~/Library/LaunchAgents/ and loaded immediately. The agent runs as
the current user.

Tokens
------
Agent tokens are created in the NetAudit dashboard under
Users > (select user) > Agent Token.

Commands
--------
  python3 agent.py start      Start manually (for testing)
  python3 agent.py status     Show ClamAV / config / LaunchAgent state
  python3 agent.py scan       Run a quick virus scan immediately
  python3 agent.py uninstall  Unload and remove LaunchAgent
""",
}


@router.get("/download/{platform}")
@limiter.limit("10/minute")
async def download_agent(
    platform: str,
    request: Request,
    current_user: User = Depends(get_current_admin),
):
    platform = platform.lower()
    if platform not in PLATFORM_FILES:
        raise HTTPException(status_code=404, detail="Unknown platform. Use: windows, linux, macos")

    if not AGENT_FILES_DIR.exists():
        raise HTTPException(status_code=500, detail="Agent files not found on server")

    dashboard_url = str(request.base_url).rstrip("/")
    readme = READMES[platform].format(dashboard_url=dashboard_url)

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename in PLATFORM_FILES[platform]:
            src = AGENT_FILES_DIR / filename
            if src.exists():
                zf.write(src, filename)

        zf.writestr("README.txt", readme)

    buf.seek(0)
    zip_name = f"netaudit-agent-{platform}.zip"

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{zip_name}"'},
    )
