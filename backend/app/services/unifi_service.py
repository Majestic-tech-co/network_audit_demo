"""
UniFi OS API client for UDM Pro / UniFi Network Application.
Uses X-API-KEY header authentication (UniFi OS 3.x+).
SSL verification is disabled because UDM Pros use self-signed certificates.
"""
import httpx
import structlog
from typing import Optional

log = structlog.get_logger()

DEVICE_TYPE_MAP = {
    "usw": "switch",
    "uap": "access_point",
    "ugw": "gateway",
    "udm": "gateway",
    "uxg": "gateway",
    "usg": "gateway",
    "uph": "phone",
    "uck": "controller",
}


class UniFiService:
    def __init__(self, host: str, api_key: str, site: str = "default"):
        self.host = host.rstrip("/")
        self.site = site
        self._headers = {
            "X-API-KEY": api_key,
            "Content-Type": "application/json",
        }

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=self._headers,
            verify=False,
            timeout=15.0,
        )

    async def test_connection(self) -> tuple[bool, str]:
        try:
            async with self._client() as client:
                r = await client.get(f"{self.host}/proxy/network/api/s/{self.site}/stat/health")
                if r.status_code == 200:
                    return True, "Connection successful"
                return False, f"Unexpected status {r.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect — check host URL and network reachability"
        except httpx.TimeoutException:
            return False, "Connection timed out"
        except Exception as e:
            log.error("unifi_test_failed", error=type(e).__name__)
            return False, "Unexpected error while testing the UniFi connection"

    async def get_infrastructure_devices(self) -> list[dict]:
        """Return UniFi-managed devices (APs, switches, gateways)."""
        async with self._client() as client:
            r = await client.get(f"{self.host}/proxy/network/api/s/{self.site}/stat/device")
            r.raise_for_status()
            devices = r.json().get("data", [])

        result = []
        for d in devices:
            model_type = d.get("type", "")
            result.append({
                "ip": d.get("ip") or d.get("config_network", {}).get("ip"),
                "mac": d.get("mac"),
                "hostname": d.get("name") or d.get("hostname"),
                "device_type": DEVICE_TYPE_MAP.get(model_type, "network_device"),
                "model": d.get("model"),
                "version": d.get("version"),
                "uptime": d.get("uptime"),
                "state": d.get("state"),  # 1 = connected
                "unifi_type": model_type,
            })
        return [d for d in result if d["ip"]]

    async def get_client_devices(self) -> list[dict]:
        """Return connected client devices (workstations, phones, etc.)."""
        async with self._client() as client:
            r = await client.get(f"{self.host}/proxy/network/api/s/{self.site}/stat/sta")
            r.raise_for_status()
            clients = r.json().get("data", [])

        result = []
        for c in clients:
            result.append({
                "ip": c.get("ip"),
                "mac": c.get("mac"),
                "hostname": c.get("hostname") or c.get("name"),
                "device_type": "workstation",
                "os_guess": c.get("os_name"),
                "ap_mac": c.get("ap_mac"),
                "network": c.get("network"),
                "is_wireless": not c.get("is_wired", True),
            })
        return [c for c in result if c["ip"]]

    async def get_all_devices(self) -> dict:
        """Return both infrastructure and client device lists."""
        infra = await self.get_infrastructure_devices()
        clients = await self.get_client_devices()
        return {"infrastructure": infra, "clients": clients}
