"""
LLDP topology discovery via Scapy passive capture.

Sniffs for LLDP frames (EtherType 0x88cc) on the host interface.
Each LLDP frame carries: Chassis ID (usually MAC), Port ID, System Name,
Management Address, and System Capabilities.

Capabilities decoded:
  bit 2 → Bridge (switch)
  bit 4 → WLAN Access Point
  bit 6 → Router
  bit 7 → Telephone / VoIP

These let us confirm device types and identify leaf vs aggregation switches.
"""
import threading
from typing import Optional
import structlog

log = structlog.get_logger()

# LLDP TLV type codes
_END       = 0
_CHASSIS   = 1
_PORT      = 2
_TTL       = 3
_PORT_DESC = 4
_SYS_NAME  = 5
_SYS_DESC  = 6
_SYS_CAP   = 7
_MGMT_ADDR = 8

# System capability bit positions (in the enabled-capabilities field)
_CAP_BRIDGE  = 1 << 2   # 0x0004
_CAP_WLAN    = 1 << 4   # 0x0010
_CAP_ROUTER  = 1 << 6   # 0x0040
_CAP_STATION = 1 << 8   # 0x0100


class LLDPService:
    """Passively captures LLDP frames and returns structured neighbor info."""

    def discover_neighbors(self, interface: str, timeout: int = 35) -> list[dict]:
        """
        Sniff LLDP on `interface` for `timeout` seconds.
        Returns one dict per unique source MAC that sent an LLDP frame.
        """
        try:
            from scapy.all import sniff, Ether
        except ImportError:
            log.error("lldp_scapy_missing")
            return []

        seen: dict[str, dict] = {}
        lock = threading.Lock()

        def _handle(pkt):
            try:
                if not (pkt.haslayer(Ether) and pkt[Ether].type == 0x88CC):
                    return
                src_mac = pkt[Ether].src.lower()
                parsed = self._parse_pdu(bytes(pkt[Ether].payload))
                if parsed:
                    parsed["source_mac"] = src_mac
                    with lock:
                        existing = seen.get(src_mac, {})
                        # Later frames can fill in fields missing from the first
                        existing.update({k: v for k, v in parsed.items() if v})
                        seen[src_mac] = existing
            except Exception:
                pass

        log.info("lldp_capture_start", interface=interface, timeout=timeout)
        try:
            sniff(
                iface=interface,
                filter="ether proto 0x88cc",
                prn=_handle,
                timeout=timeout,
                store=False,
            )
        except Exception as exc:
            log.error("lldp_sniff_error", error=str(exc))
            return []

        result = list(seen.values())
        log.info("lldp_capture_done", devices_seen=len(result))
        return result

    # ── Low-level PDU parser ────────────────────────────────────────

    def _parse_pdu(self, data: bytes) -> Optional[dict]:
        out: dict = {}
        pos = 0
        while pos + 2 <= len(data):
            try:
                word     = int.from_bytes(data[pos:pos + 2], "big")
                tlv_type = (word >> 9) & 0x7F
                tlv_len  = word & 0x1FF
                pos += 2
                if pos + tlv_len > len(data):
                    break
                value = data[pos:pos + tlv_len]
                pos += tlv_len
                if tlv_type == _END:
                    break
                self._decode_tlv(tlv_type, value, out)
            except Exception:
                break

        has_id = out.get("remote_ip") or out.get("remote_hostname") or out.get("remote_mac")
        return out if has_id else None

    def _decode_tlv(self, tlv_type: int, value: bytes, out: dict):
        if tlv_type == _CHASSIS and len(value) >= 2:
            subtype = value[0]
            if subtype == 4:  # MAC address
                out["remote_mac"] = ":".join(f"{b:02x}" for b in value[1:7])
            elif subtype in (5, 7):  # Network or local address as string
                try:
                    out["remote_chassis_str"] = value[1:].decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    pass

        elif tlv_type == _PORT and len(value) >= 2:
            subtype = value[0]
            try:
                port_str = value[1:].decode("utf-8", errors="replace").strip("\x00")
                if subtype != 3:  # skip raw MAC subtype (subtype 3)
                    out["remote_port"] = port_str
            except Exception:
                pass

        elif tlv_type == _SYS_NAME:
            try:
                out["remote_hostname"] = value.decode("utf-8", errors="replace").strip("\x00")
            except Exception:
                pass

        elif tlv_type == _SYS_DESC:
            try:
                out["remote_description"] = value.decode("utf-8", errors="replace").strip("\x00")[:200]
            except Exception:
                pass

        elif tlv_type == _SYS_CAP and len(value) >= 4:
            # Bytes 0-1: supported caps, bytes 2-3: enabled caps
            enabled = int.from_bytes(value[2:4], "big")
            out["is_bridge"]  = bool(enabled & _CAP_BRIDGE)
            out["is_wlan"]    = bool(enabled & _CAP_WLAN)
            out["is_router"]  = bool(enabled & _CAP_ROUTER)
            out["is_station"] = bool(enabled & _CAP_STATION)
            out["capabilities"] = {
                "bridge":  bool(enabled & _CAP_BRIDGE),
                "wlan":    bool(enabled & _CAP_WLAN),
                "router":  bool(enabled & _CAP_ROUTER),
                "station": bool(enabled & _CAP_STATION),
            }

        elif tlv_type == _MGMT_ADDR and len(value) >= 6:
            addr_len  = value[0]
            addr_type = value[1]
            if addr_type == 1 and addr_len == 5:   # IPv4
                out["remote_ip"] = ".".join(str(b) for b in value[2:6])

    # ── Match neighbors to known DB devices ────────────────────────

    def match_to_devices(self, neighbors: list[dict], known_devices: list) -> list[dict]:
        """
        Enrich each neighbor dict with `target_device_id` where possible,
        matching first by management IP, then by short hostname.
        """
        ip_map: dict[str, str]   = {d["ip_address"]: d["id"] for d in known_devices}
        name_map: dict[str, str] = {}
        for d in known_devices:
            if d.get("hostname"):
                name_map[d["hostname"].lower().split(".")[0]] = d["id"]

        for nb in neighbors:
            if nb.get("remote_ip") and nb["remote_ip"] in ip_map:
                nb["target_device_id"] = ip_map[nb["remote_ip"]]
                continue
            if nb.get("remote_hostname"):
                short = nb["remote_hostname"].lower().split(".")[0]
                if short in name_map:
                    nb["target_device_id"] = name_map[short]

        return neighbors
