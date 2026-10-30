// Full Wireshark-style packet capture page
import { useState, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api } from "../utils/api";
import { useAuthStore } from "../store/authStore";
import { Play, Square, Download, Trash2, Radio, ChevronDown, Clock } from "lucide-react";
import toast from "react-hot-toast";

// ─── Types ────────────────────────────────────────────────────────────────────

interface Packet {
  no: number;
  time: number;
  src: string;
  dst: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  length: number;
  info: string;
  flags: string;
}

// ─── Protocol badge colors ────────────────────────────────────────────────────

const PROTO_COLORS: Record<string, string> = {
  ARP:        "bg-yellow-100 text-yellow-800",
  DNS:        "bg-purple-100 text-purple-800",
  HTTP:       "bg-green-100 text-green-800",
  TLS:        "bg-teal-100 text-teal-800",
  SSH:        "bg-emerald-100 text-emerald-800",
  ICMP:       "bg-blue-100 text-blue-800",
  RDP:        "bg-orange-100 text-orange-800",
  SMB:        "bg-red-100 text-red-800",
  DHCP:       "bg-cyan-100 text-cyan-800",
  NTP:        "bg-indigo-100 text-indigo-800",
  SNMP:       "bg-violet-100 text-violet-800",
  TCP:        "bg-gray-100 text-gray-700",
  UDP:        "bg-slate-100 text-slate-700",
  MySQL:      "bg-orange-100 text-orange-700",
  PostgreSQL: "bg-blue-100 text-blue-700",
  Redis:      "bg-red-100 text-red-700",
  SMTP:       "bg-pink-100 text-pink-700",
  FTP:        "bg-amber-100 text-amber-700",
  Telnet:     "bg-red-100 text-red-800",
};

// ─── BPF Presets ─────────────────────────────────────────────────────────────

const BPF_PRESETS = [
  { label: "All traffic",      value: "" },
  { label: "HTTP/HTTPS",       value: "tcp port 80 or tcp port 443" },
  { label: "DNS",              value: "udp port 53" },
  { label: "ICMP (ping)",      value: "icmp" },
  { label: "ARP",              value: "arp" },
  { label: "TCP SYN only",     value: "tcp[tcpflags] & tcp-syn != 0" },
  { label: "Exclude my host",  value: "not host 127.0.0.1" },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatElapsed(s: number): string {
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

function formatAddr(ip: string, port: number | null): string {
  if (port !== null) return `${ip}:${port}`;
  return ip || "—";
}

function rowBgHint(protocol: string): string {
  if (protocol === "SMB" || protocol === "Telnet") return "bg-red-50/30";
  if (protocol === "ARP") return "bg-yellow-50/30";
  if (protocol === "DNS") return "bg-purple-50/20";
  return "";
}

// ─── Component ───────────────────────────────────────────────────────────────

export default function PacketCapturePage() {
  const [searchParams] = useSearchParams();

  // ── State
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [captureStatus, setCaptureStatus] = useState<"idle" | "running" | "stopped">("idle");
  const [packets, setPackets] = useState<Packet[]>([]);
  const [packetCount, setPacketCount] = useState<number>(0);
  const [interface_, setInterface_] = useState<string>("eth0");
  const [bpfFilter, setBpfFilter] = useState<string>("");
  const [showPresets, setShowPresets] = useState<boolean>(false);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [displayFilter, setDisplayFilter] = useState<string>("");
  const [startTime, setStartTime] = useState<number | null>(null);
  const [elapsed, setElapsed] = useState<number>(0);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);

  // ── Refs
  const wsRef = useRef<WebSocket | null>(null);
  const tableEndRef = useRef<HTMLDivElement | null>(null);
  const presetsRef = useRef<HTMLDivElement | null>(null);

  // ── Load interfaces
  const { data: ifaceData } = useQuery({
    queryKey: ["capture-interfaces"],
    queryFn: () => api.get("/api/capture/interfaces").then((r) => r.data),
  });
  const interfaces: string[] = ifaceData?.interfaces ?? ["eth0", "ens3", "wlan0"];

  // ── Populate interface select once loaded
  useEffect(() => {
    if (interfaces.length > 0 && interface_ === "eth0") {
      setInterface_(interfaces[0]);
    }
  }, [interfaces]);

  // ── Handle host pre-filter from query param
  useEffect(() => {
    const host = searchParams.get("host");
    if (host) setBpfFilter(`host ${host}`);
  }, []);

  // ── Elapsed timer
  useEffect(() => {
    if (captureStatus !== "running") return;
    const interval = setInterval(() => {
      setElapsed(Math.floor((Date.now() - (startTime ?? Date.now())) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [captureStatus, startTime]);

  // ── Auto-scroll
  useEffect(() => {
    if (autoScroll && tableEndRef.current) {
      tableEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [packets, autoScroll]);

  // ── Close presets dropdown on outside click
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (presetsRef.current && !presetsRef.current.contains(e.target as Node)) {
        setShowPresets(false);
      }
    }
    if (showPresets) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [showPresets]);

  // ── Cleanup WS on unmount
  useEffect(() => {
    return () => {
      wsRef.current?.close();
    };
  }, []);

  // ── Start capture
  async function startCapture() {
    try {
      const res = await api.post("/api/capture/start", {
        interface: interface_,
        bpf_filter: bpfFilter,
        max_packets: 5000,
      });
      const { session_id } = res.data;
      setSessionId(session_id);
      setCaptureStatus("running");
      setPackets([]);
      setPacketCount(0);
      setStartTime(Date.now());
      setElapsed(0);
      setSelectedPacket(null);

      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const wsUrl = `${proto}://${window.location.host}/ws/capture/${session_id}?token=${useAuthStore.getState().accessToken}`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.event) return;
          setPackets((prev) => {
            const next = [...prev, data as Packet];
            return next.length > 2000 ? next.slice(-2000) : next;
          });
          setPacketCount((data as Packet).no);
        } catch {
          // ignore parse errors
        }
      };

      ws.onerror = () => toast.error("WebSocket error — check network interface name");
      ws.onclose = () =>
        setCaptureStatus((prev) => (prev === "running" ? "stopped" : prev));
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Failed to start capture");
    }
  }

  // ── Stop capture
  async function stopCapture() {
    if (!sessionId) return;
    try {
      await api.post(`/api/capture/${sessionId}/stop`);
    } catch {
      // best-effort
    }
    wsRef.current?.close();
    setCaptureStatus("stopped");
  }

  // ── Client-side display filter
  const filteredPackets = displayFilter.trim()
    ? packets.filter(
        (p) =>
          p.src.includes(displayFilter) ||
          p.dst.includes(displayFilter) ||
          p.protocol.toLowerCase().includes(displayFilter.toLowerCase()) ||
          p.info.toLowerCase().includes(displayFilter.toLowerCase()) ||
          p.src_port?.toString() === displayFilter ||
          p.dst_port?.toString() === displayFilter
      )
    : packets;

  // ── Relative time formatting
  function formatTime(pktTime: number): string {
    if (!startTime) return pktTime.toFixed(6);
    const rel = pktTime - startTime / 1000;
    return rel.toFixed(6);
  }

  // ─── Render ──────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-full">

      {/* ── Top header ── */}
      <div className="bg-white border-b border-gray-200 px-6 py-4 flex items-center gap-3">
        <Radio className="w-5 h-5 text-purple-600" />
        <h1 className="text-lg font-semibold text-gray-900">Packet Capture</h1>
        {captureStatus === "running" && (
          <span className="flex items-center gap-1.5 ml-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500" />
            </span>
            <span className="text-xs text-green-600 font-medium">Capturing</span>
          </span>
        )}
        {captureStatus === "stopped" && (
          <span className="flex items-center gap-1.5 ml-2">
            <span className="inline-flex rounded-full h-2.5 w-2.5 bg-gray-400" />
            <span className="text-xs text-gray-500 font-medium">Stopped</span>
          </span>
        )}
      </div>

      {/* ── Controls bar ── */}
      <div className="bg-white border-b border-gray-200 px-4 py-3 flex flex-wrap gap-3 items-center">
        {/* Interface selector */}
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500 font-medium whitespace-nowrap">Interface</label>
          <select
            value={interface_}
            onChange={(e) => setInterface_(e.target.value)}
            disabled={captureStatus === "running"}
            className="text-sm border border-gray-300 rounded-md px-2 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-purple-400 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {interfaces.map((iface) => (
              <option key={iface} value={iface}>
                {iface}
              </option>
            ))}
          </select>
        </div>

        {/* BPF filter input */}
        <div className="flex items-center gap-2 flex-1 min-w-48">
          <label className="text-xs text-gray-500 font-medium whitespace-nowrap">BPF Filter</label>
          <input
            type="text"
            value={bpfFilter}
            onChange={(e) => setBpfFilter(e.target.value)}
            disabled={captureStatus === "running"}
            placeholder="Filter expression (e.g. host 192.168.0.1)"
            className="flex-1 text-sm border border-gray-300 rounded-md px-3 py-1.5 font-mono focus:outline-none focus:ring-2 focus:ring-purple-400 disabled:opacity-50 disabled:cursor-not-allowed"
          />
        </div>

        {/* Presets dropdown */}
        <div className="relative" ref={presetsRef}>
          <button
            onClick={() => setShowPresets((v) => !v)}
            disabled={captureStatus === "running"}
            className="flex items-center gap-1 text-sm border border-gray-300 rounded-md px-3 py-1.5 bg-white hover:bg-gray-50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Presets
            <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
          </button>
          {showPresets && (
            <div className="absolute top-full left-0 mt-1 z-50 bg-white border border-gray-200 rounded-lg shadow-lg min-w-52 py-1">
              {BPF_PRESETS.map((preset) => (
                <button
                  key={preset.label}
                  onClick={() => {
                    setBpfFilter(preset.value);
                    setShowPresets(false);
                  }}
                  className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  <div className="font-medium">{preset.label}</div>
                  {preset.value && (
                    <div className="text-xs text-gray-400 font-mono truncate mt-0.5">{preset.value}</div>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Start button */}
        <button
          onClick={startCapture}
          disabled={captureStatus === "running"}
          className="flex items-center gap-2 px-4 py-1.5 bg-green-600 text-white text-sm font-medium rounded-md hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Play className="w-4 h-4" />
          Start Capture
        </button>

        {/* Stop button */}
        <button
          onClick={stopCapture}
          disabled={captureStatus !== "running"}
          className="flex items-center gap-2 px-4 py-1.5 bg-red-600 text-white text-sm font-medium rounded-md hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Square className="w-4 h-4" />
          Stop
        </button>
      </div>

      {/* ── Stats / toolbar bar ── */}
      <div className="bg-gray-50 border-b border-gray-200 px-4 py-2 flex flex-wrap gap-4 items-center text-sm">
        {/* Display filter */}
        <input
          type="text"
          placeholder="Search packets..."
          value={displayFilter}
          onChange={(e) => setDisplayFilter(e.target.value)}
          className="text-sm border border-gray-300 rounded-md px-3 py-1 focus:outline-none focus:ring-2 focus:ring-purple-400 w-52"
        />

        {/* Packet counter */}
        <span className="text-gray-500">
          <span className="font-medium text-gray-700">{packetCount.toLocaleString()}</span> captured
        </span>

        {/* Shown count (when filtering) */}
        {displayFilter.trim() && (
          <span className="text-gray-500">
            <span className="font-medium text-gray-700">{filteredPackets.length.toLocaleString()}</span> shown
          </span>
        )}

        {/* Elapsed timer */}
        <span className="flex items-center gap-1.5 text-gray-500">
          <Clock className="w-3.5 h-3.5" />
          {formatElapsed(elapsed)}
        </span>

        {/* Auto-scroll toggle */}
        <label className="flex items-center gap-1.5 text-gray-600 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            className="rounded border-gray-300 text-purple-600 focus:ring-purple-400"
          />
          Auto-scroll
        </label>

        <div className="flex items-center gap-2 ml-auto">
          {/* Clear button */}
          {packets.length > 0 && (
            <button
              onClick={() => {
                setPackets([]);
                setPacketCount(0);
                setSelectedPacket(null);
                setElapsed(0);
                setStartTime(null);
              }}
              className="flex items-center gap-1.5 px-3 py-1 text-sm text-gray-600 border border-gray-300 rounded-md hover:bg-gray-100 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear
            </button>
          )}

          {/* Export PCAP */}
          {sessionId && captureStatus !== "idle" && (
            <a
              href={`/api/capture/${sessionId}/export`}
              download={`capture-${sessionId.slice(0, 8)}.pcap`}
              className="flex items-center gap-1.5 px-3 py-1 text-sm text-blue-600 border border-blue-300 rounded-md hover:bg-blue-50 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Export PCAP
            </a>
          )}
        </div>
      </div>

      {/* ── Packet table ── */}
      <div className="flex-1 overflow-auto font-mono text-xs">
        {filteredPackets.length === 0 && captureStatus !== "running" ? (
          /* Empty state */
          <div className="flex flex-col items-center justify-center h-full text-gray-400 gap-3">
            <Radio className="w-12 h-12 text-gray-300" />
            <div className="text-base font-medium text-gray-500">No packets captured yet</div>
            <div className="text-sm text-gray-400">Select an interface and click Start Capture</div>
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 z-10">
              <tr className="bg-gray-100 border-b border-gray-300 text-left">
                <th className="px-2 py-1.5 w-16 text-right text-gray-600 font-semibold">No.</th>
                <th className="px-2 py-1.5 w-28 text-gray-600 font-semibold">Time</th>
                <th className="px-2 py-1.5 w-40 text-gray-600 font-semibold">Source</th>
                <th className="px-2 py-1.5 w-40 text-gray-600 font-semibold">Destination</th>
                <th className="px-2 py-1.5 w-24 text-gray-600 font-semibold">Protocol</th>
                <th className="px-2 py-1.5 w-16 text-right text-gray-600 font-semibold">Len</th>
                <th className="px-2 py-1.5 text-gray-600 font-semibold">Info</th>
              </tr>
            </thead>
            <tbody>
              {filteredPackets.map((pkt) => {
                const isSelected = selectedPacket?.no === pkt.no;
                const rowHint = rowBgHint(pkt.protocol);
                return (
                  <tr
                    key={pkt.no}
                    onClick={() => setSelectedPacket(isSelected ? null : pkt)}
                    className={`border-b border-gray-100 cursor-pointer transition-colors ${
                      isSelected
                        ? "bg-blue-50"
                        : `hover:bg-gray-50 ${rowHint}`
                    }`}
                  >
                    <td className="px-2 py-0.5 w-16 text-right text-gray-400">{pkt.no}</td>
                    <td className="px-2 py-0.5 w-28 text-gray-500">{formatTime(pkt.time)}</td>
                    <td className="px-2 py-0.5 w-40 truncate text-gray-700">{formatAddr(pkt.src, pkt.src_port)}</td>
                    <td className="px-2 py-0.5 w-40 truncate text-gray-700">{formatAddr(pkt.dst, pkt.dst_port)}</td>
                    <td className="px-2 py-0.5 w-24">
                      <span
                        className={`inline-block px-1.5 py-0.5 rounded text-xs font-medium leading-tight ${
                          PROTO_COLORS[pkt.protocol] ?? "bg-gray-100 text-gray-600"
                        }`}
                      >
                        {pkt.protocol}
                      </span>
                    </td>
                    <td className="px-2 py-0.5 w-16 text-right text-gray-500">{pkt.length}</td>
                    <td className="px-2 py-0.5 text-gray-600 truncate max-w-0 overflow-hidden">{pkt.info}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        <div ref={tableEndRef} />
      </div>

      {/* ── Detail panel ── */}
      {selectedPacket && (
        <div className="bg-white border-t border-gray-200 p-4 h-40 overflow-y-auto shrink-0">
          <div className="text-xs font-semibold text-gray-500 mb-2 uppercase tracking-wide">Packet Detail</div>
          <div className="grid grid-cols-5 gap-x-6 gap-y-1 text-xs mb-2">
            <div>
              <span className="text-gray-400">No.</span>
              <span className="ml-1 font-medium text-gray-700 font-mono">{selectedPacket.no}</span>
            </div>
            <div>
              <span className="text-gray-400">Protocol</span>
              <span className={`ml-1 inline-block px-1.5 py-0.5 rounded text-xs font-medium leading-tight ${PROTO_COLORS[selectedPacket.protocol] ?? "bg-gray-100 text-gray-600"}`}>
                {selectedPacket.protocol}
              </span>
            </div>
            <div>
              <span className="text-gray-400">Time</span>
              <span className="ml-1 font-mono text-gray-700">{formatTime(selectedPacket.time)}</span>
            </div>
            <div>
              <span className="text-gray-400">Length</span>
              <span className="ml-1 font-mono text-gray-700">{selectedPacket.length} B</span>
            </div>
            <div>
              <span className="text-gray-400">Flags</span>
              <span className="ml-1 font-mono text-gray-700">{selectedPacket.flags || "—"}</span>
            </div>
          </div>
          <div className="text-xs mb-1">
            <span className="font-mono text-gray-700">{formatAddr(selectedPacket.src, selectedPacket.src_port)}</span>
            <span className="text-gray-400 mx-2">→</span>
            <span className="font-mono text-gray-700">{formatAddr(selectedPacket.dst, selectedPacket.dst_port)}</span>
          </div>
          {selectedPacket.info && (
            <div className="text-xs text-gray-500 font-mono truncate">{selectedPacket.info}</div>
          )}
        </div>
      )}
    </div>
  );
}
