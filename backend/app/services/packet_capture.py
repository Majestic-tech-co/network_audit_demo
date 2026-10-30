"""
Packet parsing utilities for live capture.
Converts raw scapy packets into JSON-serialisable dicts.
"""
import structlog

log = structlog.get_logger()


def parse_packet(pkt) -> dict:
    """Parse a scapy packet into a JSON-serialisable summary dict."""
    result = {
        "time": float(pkt.time),
        "src": "",
        "dst": "",
        "src_port": None,
        "dst_port": None,
        "protocol": "Other",
        "length": len(pkt),
        "info": "",
        "flags": "",
    }
    try:
        from scapy.layers.l2 import ARP
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns import DNS

        if ARP in pkt:
            arp = pkt[ARP]
            result["protocol"] = "ARP"
            result["src"] = arp.psrc
            result["dst"] = arp.pdst
            if arp.op == 1:
                result["info"] = f"Who has {arp.pdst}? Tell {arp.psrc}"
            else:
                result["info"] = f"{arp.psrc} is at {arp.hwsrc}"

        elif IP in pkt:
            ip = pkt[IP]
            result["src"] = ip.src
            result["dst"] = ip.dst

            if ICMP in pkt:
                icmp = pkt[ICMP]
                result["protocol"] = "ICMP"
                icmp_info = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable", 11: "TTL Exceeded"}
                result["info"] = icmp_info.get(icmp.type, f"Type {icmp.type}")

            elif TCP in pkt:
                tcp = pkt[TCP]
                sport, dport = tcp.sport, tcp.dport
                result["src_port"] = sport
                result["dst_port"] = dport

                port_protocols = {
                    80: "HTTP", 8080: "HTTP", 443: "TLS", 8443: "TLS",
                    22: "SSH", 3389: "RDP", 445: "SMB", 3306: "MySQL",
                    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
                    25: "SMTP", 587: "SMTP", 993: "IMAPS", 143: "IMAP",
                    21: "FTP", 23: "Telnet",
                }
                result["protocol"] = port_protocols.get(dport) or port_protocols.get(sport) or "TCP"

                # Build flags string
                flag_bits = int(tcp.flags)
                flag_parts = []
                if flag_bits & 0x02: flag_parts.append("SYN")
                if flag_bits & 0x10: flag_parts.append("ACK")
                if flag_bits & 0x01: flag_parts.append("FIN")
                if flag_bits & 0x04: flag_parts.append("RST")
                if flag_bits & 0x08: flag_parts.append("PSH")
                if flag_bits & 0x20: flag_parts.append("URG")
                result["flags"] = " ".join(flag_parts)
                result["info"] = f"{sport} → {dport} [{result['flags']}] Seq={tcp.seq}"

            elif UDP in pkt:
                udp = pkt[UDP]
                sport, dport = udp.sport, udp.dport
                result["src_port"] = sport
                result["dst_port"] = dport

                if dport == 53 or sport == 53 or dport == 5353 or sport == 5353:
                    result["protocol"] = "DNS"
                    if DNS in pkt and pkt[DNS].qd:
                        try:
                            qname = pkt[DNS].qd.qname.decode(errors="replace").rstrip(".")
                            result["info"] = f"Query: {qname}" if pkt[DNS].qr == 0 else f"Response: {qname}"
                        except Exception:
                            result["info"] = "DNS"
                    else:
                        result["info"] = "DNS"
                elif dport in (67, 68):
                    result["protocol"] = "DHCP"
                    result["info"] = f"DHCP {sport} → {dport}"
                elif dport == 123 or sport == 123:
                    result["protocol"] = "NTP"
                    result["info"] = "NTP time sync"
                elif dport in (161, 162) or sport in (161, 162):
                    result["protocol"] = "SNMP"
                    result["info"] = f"{sport} → {dport}"
                else:
                    result["protocol"] = "UDP"
                    result["info"] = f"{sport} → {dport} Len={udp.len}"

    except Exception as e:
        log.warning("packet_parse_error", error=str(e))

    return result


def get_host_interfaces() -> list:
    """Return sorted list of non-loopback, non-virtual network interfaces."""
    try:
        import psutil
        skip_prefixes = ("lo", "docker", "br-", "veth", "virbr", "tun", "tap")
        ifaces = sorted([
            name for name in psutil.net_if_addrs()
            if not any(name.startswith(p) for p in skip_prefixes)
        ])
        return ifaces if ifaces else ["eth0"]
    except Exception:
        return ["eth0", "ens3", "ens18", "wlan0"]
