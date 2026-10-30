import { useEffect, useRef, useCallback } from "react";
import { useAuthStore } from "../store/authStore";

export type ScanEvent =
  | { event: "connected"; org_id: string }
  | { event: "scan_started"; scan_id: string; payload: { scan_type: string; target: string; message: string } }
  | { event: "scan_progress"; scan_id: string; payload: { percent: number; message: string; hosts_found?: number } }
  | { event: "scan_complete"; scan_id: string; payload: { percent: number; hosts_discovered: number; findings_count: number; message: string } }
  | { event: "scan_failed"; scan_id: string; payload: { message: string } }
  | { event: "finding_created"; scan_id: string; payload: { finding: any } };

type EventHandler = (event: ScanEvent) => void;

export function useWebSocket(onEvent: EventHandler) {
  const { user, accessToken } = useAuthStore();
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    if (!user?.organization_id || !accessToken) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/ws/${user.organization_id}?token=${accessToken}`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      // Start keepalive pings every 30s
      const ping = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send("ping");
      }, 30_000);
      ws.addEventListener("close", () => clearInterval(ping));
    };

    ws.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data) as ScanEvent;
        onEvent(event);
      } catch {}
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      // Reconnect after 3 seconds
      reconnectTimer.current = setTimeout(() => {
        if (mountedRef.current) connect();
      }, 3_000);
    };

    ws.onerror = () => ws.close();
  }, [user?.organization_id, accessToken]);

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);
}
