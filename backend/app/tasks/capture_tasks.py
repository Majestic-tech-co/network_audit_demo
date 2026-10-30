"""
Celery tasks for live packet capture.
Runs in the worker container (network_mode: host) so scapy can see
real host network interfaces.
"""
import json
import os
import time
import threading
import structlog

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.packet_capture import parse_packet, get_host_interfaces

log = structlog.get_logger()

CAPTURES_DIR = "/app/scan_results/captures"


@celery_app.task(name="register_interfaces")
def register_interfaces():
    """Store available network interfaces in Redis. Called on worker startup."""
    import redis as sync_redis
    try:
        ifaces = get_host_interfaces()
        r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
        r.set("capture:host:interfaces", json.dumps(ifaces), ex=86400)
        r.close()
        log.info("interfaces_registered", interfaces=ifaces)
    except Exception as e:
        log.error("register_interfaces_failed", error=str(e))


@celery_app.task(name="run_capture", bind=True)
def run_capture(self, session_id: str, interface: str, bpf_filter: str, max_packets: int = 5000):
    """
    Capture packets on the given interface and stream them to Redis pub/sub.
    Stops when: Redis stop signal is set, max_packets reached, or task is revoked.
    """
    import redis as sync_redis

    r = sync_redis.from_url(settings.REDIS_URL, decode_responses=False)

    try:
        # Mark session as running
        r.setex(f"capture:{session_id}:status", 7200, b"running")
        r.setex(f"capture:{session_id}:count", 7200, b"0")

        # Prepare PCAP output
        os.makedirs(CAPTURES_DIR, exist_ok=True)
        pcap_path = os.path.join(CAPTURES_DIR, f"{session_id}.pcap")

        from scapy.utils import PcapWriter
        from scapy.config import conf as scapy_conf
        scapy_conf.verb = 0

        pcap_writer = PcapWriter(pcap_path, append=False, sync=True)
        pcap_lock = threading.Lock()
        packet_count = 0

        def on_packet(pkt):
            nonlocal packet_count
            try:
                status_raw = r.get(f"capture:{session_id}:status")
                if not status_raw or status_raw.decode() != "running":
                    return
                if packet_count >= max_packets:
                    return

                parsed = parse_packet(pkt)
                packet_count += 1
                parsed["no"] = packet_count

                # Stream to WebSocket subscribers
                r.publish(f"capture:{session_id}:stream", json.dumps(parsed))
                r.setex(f"capture:{session_id}:count", 7200, str(packet_count).encode())

                # Write to PCAP
                with pcap_lock:
                    pcap_writer.write(pkt)

            except Exception as e:
                log.warning("on_packet_error", error=str(e))

        from scapy.all import AsyncSniffer

        sniffer = AsyncSniffer(
            iface=interface,
            filter=bpf_filter if bpf_filter else None,
            prn=on_packet,
            store=False,
            promisc=True,
        )

        log.info("capture_started", session_id=session_id, interface=interface, filter=bpf_filter)
        sniffer.start()

        while True:
            status_raw = r.get(f"capture:{session_id}:status")
            status = status_raw.decode() if status_raw else "stopped"
            if status != "running" or packet_count >= max_packets:
                break
            time.sleep(0.3)

    except Exception as e:
        log.error("capture_task_failed", session_id=session_id, error=str(e))
        r.setex(f"capture:{session_id}:status", 7200, b"error")
        r.setex(f"capture:{session_id}:error", 7200, b"Capture failed. Check the server logs for details.")
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
        try:
            with pcap_lock:
                pcap_writer.close()
        except Exception:
            pass
        r.set(f"capture:{session_id}:status", b"stopped")
        try:
            r.close()
        except Exception:
            pass
        log.info("capture_stopped", session_id=session_id, packets=packet_count)


# Register available interfaces when the worker starts
from celery.signals import worker_ready

@worker_ready.connect
def on_worker_ready(sender, **kwargs):
    register_interfaces.delay()
