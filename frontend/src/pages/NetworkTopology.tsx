import { useCallback, useEffect, useState } from "react";
import ReactFlow, {
  Node, Edge, Background, Controls, MiniMap,
  useNodesState, useEdgesState, NodeTypes,
  Handle, Position,
} from "reactflow";
import "reactflow/dist/style.css";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../utils/api";
import FindingDetailPanel from "../components/topology/FindingDetailPanel";
import {
  Shield, AlertTriangle, Monitor, Printer, Server,
  Network, Wifi, HelpCircle, ScanLine, CheckCircle2, Loader2,
} from "lucide-react";

// ─── Helpers ───────────────────────────────────────────────────────

function riskLevel(score: number): "critical" | "high" | "medium" | "low" | "clean" {
  return score > 80 ? "critical"
    : score > 60 ? "high"
    : score > 30 ? "medium"
    : score > 10 ? "low"
    : "clean";
}

const RISK_COLORS = {
  critical: { border: "#ef4444", bg: "#fef2f2", dot: "bg-red-500" },
  high:     { border: "#f97316", bg: "#fff7ed", dot: "bg-orange-500" },
  medium:   { border: "#f59e0b", bg: "#fffbeb", dot: "bg-amber-500" },
  low:      { border: "#3b82f6", bg: "#eff6ff", dot: "bg-blue-500" },
  clean:    { border: "#22c55e", bg: "#f0fdf4", dot: "bg-green-500" },
};

const GATEWAY_TYPES = new Set(["gateway", "router", "ugw", "udm", "uxg", "usg", "firewall"]);
const SWITCH_TYPES  = new Set(["switch", "usw"]);
const AP_TYPES      = new Set(["access_point", "uap", "wireless_ap"]);
const INFRA_TYPES   = new Set([...GATEWAY_TYPES, ...SWITCH_TYPES, ...AP_TYPES]);

// Derive the canonical type for a device, applying the same hostname inference
// used by the backend so the map works correctly even before a rescan.
function resolveType(device: any): string {
  const raw = (device.device_type || "").toLowerCase();
  if (raw && raw !== "unknown" && raw !== "general purpose") return raw;
  const h = (device.hostname || "").toLowerCase();
  if (!h) return "unknown";
  if (/^usw-/.test(h) || /^us-\d/.test(h)) return "switch";
  if (/^u[67]-/.test(h) || /^uap-/.test(h)) return "access_point";
  if (h === "unifi" || /^(udm|usg|uxg|ugw)/.test(h)) return "gateway";
  if (/(router|gateway|firewall|pfsense|fw-)/.test(h)) return "gateway";
  if (/(switch|-sw-)/.test(h)) return "switch";
  if (/(wifi|wireless|-ap-|-ap$|^ap-)/.test(h)) return "access_point";
  if (/^(desktop|laptop|workstation|pc)-/.test(h) || /desktop-/.test(h)) return "workstation";
  if (/(printer|ricoh|xerox)/.test(h)) return "printer";
  if (/(server|srv|gitlab|proxmox|esxi|nginx|docker|kimai|hrm)/.test(h)) return "server";
  return "unknown";
}

function subnet3(ip: string) {
  return ip.split(".").slice(0, 3).join(".");
}

function lastOctet(ip: string): number {
  return parseInt(ip.split(".").pop() ?? "0", 10);
}

// Find the switch whose IP is numerically closest to the device IP.
// Used when all switches share the same /24 (flat network).
function nearestSwitch(deviceIp: string, switches: any[]): string {
  const ep = lastOctet(deviceIp);
  return switches.reduce((best, sw) => {
    return Math.abs(ep - lastOctet(sw.ip_address)) <
           Math.abs(ep - lastOctet(best.ip_address))
      ? sw : best;
  }).id;
}

// ─── Custom Nodes ─────────────────────────────────────────────────

function GatewayNode({ data }: { data: any }) {
  return (
    <div
      style={{
        background: "#0f172a",
        border: "2px solid #334155",
        borderRadius: 12,
        padding: "12px 18px",
        minWidth: 150,
        textAlign: "center",
        cursor: data.device ? "pointer" : "default",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Shield className="w-5 h-5 text-blue-400 mx-auto mb-1" />
      <div className="text-xs font-semibold text-white truncate max-w-[130px] mx-auto">
        {data.label}
      </div>
      <div className="text-xs text-slate-400 mt-0.5">{data.ip}</div>
      {data.synthetic && (
        <div className="text-xs text-slate-500 mt-0.5 italic">auto-detected</div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ background: "#475569" }} />
    </div>
  );
}

function SwitchNode({ data }: { data: any }) {
  const isAP = AP_TYPES.has(data.deviceType);
  const Icon = isAP ? Wifi : Network;
  const risk = data.device ? RISK_COLORS[riskLevel(data.device.risk_score)] : null;

  return (
    <div
      style={{
        background: "#1e3a5f",
        border: `2px solid ${risk ? risk.border : "#1d4ed8"}`,
        borderRadius: 10,
        padding: "10px 16px",
        minWidth: 150,
        textAlign: "center",
        cursor: "pointer",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: "#3b82f6" }} />
      <div className="flex items-center justify-center gap-2 mb-1">
        <Icon className="w-4 h-4 text-blue-300" />
        {risk && data.device?.open_findings_count > 0 && (
          <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
        )}
      </div>
      <div className="text-xs font-semibold text-white truncate max-w-[130px] mx-auto">
        {data.label}
      </div>
      <div className="text-xs text-blue-300 mt-0.5">{data.ip}</div>
      <div className="text-xs text-slate-400 mt-1 flex items-center justify-center gap-1">
        {isAP ? "Access Point" : "Switch"} · {data.connectedCount} device{data.connectedCount !== 1 ? "s" : ""}
        {data.lldpConfirmed && (
          <CheckCircle2 className="w-3 h-3 text-green-400 flex-shrink-0" />
        )}
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: "#3b82f6" }} />
    </div>
  );
}

function DeviceNode({ data }: { data: any }) {
  const risk = RISK_COLORS[data.risk as keyof typeof RISK_COLORS] || RISK_COLORS.clean;

  const Icon = data.deviceType === "server" ? Server
    : data.deviceType === "printer" ? Printer
    : data.deviceType === "unknown" ? HelpCircle
    : Monitor;

  return (
    <div
      style={{
        background: risk.bg,
        border: `2px solid ${risk.border}`,
        borderRadius: 10,
        padding: "10px 14px",
        minWidth: 145,
        boxShadow: "0 1px 3px rgba(0,0,0,0.08)",
        cursor: "pointer",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />

      <div className="flex items-center gap-2 mb-1">
        <Icon className="w-4 h-4 text-gray-500 flex-shrink-0" />
        <span className="text-xs font-semibold text-gray-700 truncate max-w-[90px]">
          {data.hostname || data.ip}
        </span>
        <span className={`ml-auto w-2 h-2 rounded-full flex-shrink-0 ${risk.dot}`} />
      </div>

      <div className="text-xs text-gray-400 font-mono">{data.ip}</div>

      {data.findingCount > 0 && (
        <div className="flex items-center gap-1 mt-1.5">
          <AlertTriangle className="w-3 h-3 text-red-400" />
          <span className="text-xs text-red-500 font-medium">{data.findingCount} issue{data.findingCount !== 1 ? "s" : ""}</span>
        </div>
      )}

      {data.os && (
        <div className="text-xs text-gray-300 mt-0.5 truncate">{data.os}</div>
      )}

      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes: NodeTypes = {
  gateway: GatewayNode,
  switch:  SwitchNode,
  device:  DeviceNode,
};

// ─── Layout engine ────────────────────────────────────────────────

const Y_GW       = 40;
const Y_SW       = 260;
const Y_DEVICES  = 480;
const DEVICE_W   = 180;
const DEVICE_H   = 165;
const MAX_COLS   = 5;
const GROUP_GAP  = 50;   // horizontal gap between switch groups
const CANVAS_CX  = 550;  // approximate center x

// Build a set of device IDs confirmed via LLDP, and their capability flags
function buildLldpMeta(links: any[]): {
  confirmedIds: Set<string>;
  bridgeIds: Set<string>;
  routerIds: Set<string>;
  wlanIds: Set<string>;
} {
  const confirmedIds = new Set<string>();
  const bridgeIds    = new Set<string>();
  const routerIds    = new Set<string>();
  const wlanIds      = new Set<string>();
  for (const lnk of links ?? []) {
    if (lnk.target_device_id) {
      confirmedIds.add(lnk.target_device_id);
      if (lnk.is_bridge)  bridgeIds.add(lnk.target_device_id);
      if (lnk.is_router)  routerIds.add(lnk.target_device_id);
      if (lnk.is_wlan)    wlanIds.add(lnk.target_device_id);
    }
  }
  return { confirmedIds, bridgeIds, routerIds, wlanIds };
}

function buildGraph(devices: any[], topoLinks: any[] = []): { nodes: Node[]; edges: Edge[] } {
  if (!devices?.length) return { nodes: [], edges: [] };

  const lldp = buildLldpMeta(topoLinks);

  const nodes: Node[] = [];
  const edges: Edge[] = [];

  const gateways  = devices.filter(d => GATEWAY_TYPES.has(resolveType(d)));
  const switches  = devices.filter(d => SWITCH_TYPES.has(resolveType(d)));
  const aps       = devices.filter(d => AP_TYPES.has(resolveType(d)));
  const endpoints = devices.filter(d => !INFRA_TYPES.has(resolveType(d)));
  const infra     = [...switches, ...aps];

  // ── Synthetic gateway if none discovered ──
  const syntheticGw = gateways.length === 0;
  const primaryGwId = syntheticGw ? "__gw__" : gateways[0].id;

  if (syntheticGw) {
    nodes.push({
      id: "__gw__",
      type: "gateway",
      position: { x: CANVAS_CX - 75, y: Y_GW },
      data: { label: "Gateway / Router", ip: "—", synthetic: true },
    });
  } else {
    const gwSpacing = 240;
    const gwStartX = CANVAS_CX - ((gateways.length - 1) * gwSpacing) / 2;
    gateways.forEach((gw, i) => {
      nodes.push({
        id: gw.id,
        type: "gateway",
        position: { x: gwStartX + i * gwSpacing - 75, y: Y_GW },
        data: { label: gw.hostname || gw.ip_address, ip: gw.ip_address, device: gw },
      });
    });
  }

  // ── Assign endpoints to a parent switch ──
  // Build a subnet→switchId map, but only when exactly ONE switch lives on that /24.
  // If multiple switches share the same subnet (flat network) we rely on IP proximity.
  const subnetSwitchCount = new Map<string, number>();
  infra.forEach(sw => {
    const sn = subnet3(sw.ip_address);
    subnetSwitchCount.set(sn, (subnetSwitchCount.get(sn) ?? 0) + 1);
  });
  const switchBySubnet = new Map<string, string>();
  infra.forEach(sw => {
    const sn = subnet3(sw.ip_address);
    if (subnetSwitchCount.get(sn) === 1) switchBySubnet.set(sn, sw.id);
  });

  // track children per switch
  const childrenOf = new Map<string, any[]>();
  infra.forEach(sw => childrenOf.set(sw.id, []));
  childrenOf.set(primaryGwId, []);

  // When LLDP data is available, prefer assigning endpoints to LEAF switches
  // (those without Router capability — they're edge switches, not aggregation).
  // Without LLDP, use the full infra list.
  const leafInfra = lldp.confirmedIds.size > 0
    ? infra.filter(sw => !lldp.routerIds.has(sw.id) && !lldp.bridgeIds.has(sw.id)
        ? true                                  // not in LLDP at all → treat as leaf
        : !lldp.routerIds.has(sw.id))           // in LLDP: leaf if no router bit
    : infra;
  const assignPool = leafInfra.length > 0 ? leafInfra : infra;

  endpoints.forEach(ep => {
    const sn = subnet3(ep.ip_address);
    let parentId: string = switchBySubnet.get(sn) ?? "";
    if (!parentId) {
      if (assignPool.length > 0) {
        parentId = nearestSwitch(ep.ip_address, assignPool);
      } else {
        parentId = primaryGwId;
      }
    }
    childrenOf.get(parentId)!.push(ep);
  });

  // ── Build switch columns with calculated widths ──
  interface ColDef { sw: any; children: any[]; groupW: number; centerX: number }

  if (infra.length > 0) {
    const cols: ColDef[] = infra.map(sw => {
      const children = childrenOf.get(sw.id) ?? [];
      const numCols  = Math.min(MAX_COLS, Math.max(1, children.length));
      const groupW   = Math.max(180, numCols * DEVICE_W);
      return { sw, children, groupW, centerX: 0 };
    });

    // Lay columns left-to-right, then center over canvas
    let curX = 0;
    cols.forEach(col => {
      col.centerX = curX + col.groupW / 2;
      curX += col.groupW + GROUP_GAP;
    });
    const totalW  = curX - GROUP_GAP;
    const offsetX = Math.max(0, CANVAS_CX - totalW / 2);
    cols.forEach(col => (col.centerX += offsetX));

    // Reposition gateway(s) to centre above the switch row
    const firstCx = cols[0].centerX;
    const lastCx  = cols[cols.length - 1].centerX;
    const gwCx    = (firstCx + lastCx) / 2;

    if (syntheticGw) {
      nodes.find(n => n.id === "__gw__")!.position = { x: gwCx - 75, y: Y_GW };
    } else {
      const gwSpacing = 240;
      const gwStart   = gwCx - ((gateways.length - 1) * gwSpacing) / 2;
      gateways.forEach((gw, i) => {
        nodes.find(n => n.id === gw.id)!.position = { x: gwStart + i * gwSpacing - 75, y: Y_GW };
      });
    }

    cols.forEach(col => {
      const swX      = col.centerX - 75;
      const numCols  = Math.min(MAX_COLS, Math.max(1, col.children.length));
      const childStartX = col.centerX - (numCols * DEVICE_W) / 2;

      // Switch node
      nodes.push({
        id: col.sw.id,
        type: "switch",
        position: { x: swX, y: Y_SW },
        data: {
          label: col.sw.hostname || col.sw.ip_address,
          ip: col.sw.ip_address,
          deviceType: resolveType(col.sw),
          connectedCount: col.children.length,
          lldpConfirmed: lldp.confirmedIds.has(col.sw.id),
          device: col.sw,
        },
      });

      edges.push({
        id: `e-gw-${col.sw.id}`,
        source: primaryGwId,
        target: col.sw.id,
        style: { stroke: "#475569", strokeWidth: 2 },
      });

      // Endpoint devices under this switch
      col.children.forEach((ep, i) => {
        const c    = i % numCols;
        const r    = Math.floor(i / numCols);
        const risk = riskLevel(ep.risk_score);

        nodes.push({
          id: ep.id,
          type: "device",
          position: { x: childStartX + c * DEVICE_W, y: Y_DEVICES + r * DEVICE_H },
          data: {
            ip: ep.ip_address,
            hostname: ep.hostname,
            os: ep.os_guess,
            risk,
            findingCount: ep.open_findings_count ?? 0,
            deviceType: resolveType(ep),
            device: ep,
          },
        });

        edges.push({
          id: `e-${col.sw.id}-${ep.id}`,
          source: col.sw.id,
          target: ep.id,
          style: {
            stroke: risk === "critical" ? "#ef4444"
              : risk === "high"     ? "#f97316"
              : "#cbd5e1",
            strokeWidth: risk === "critical" ? 2 : 1,
          },
          animated: risk === "critical",
        });
      });
    });

  } else {
    // No switches — flat grid directly under gateway
    const numCols  = Math.min(MAX_COLS, endpoints.length);
    const startX   = CANVAS_CX - ((numCols - 1) * DEVICE_W) / 2 - DEVICE_W / 2 + 10;

    endpoints.forEach((ep, i) => {
      const c    = i % Math.max(1, numCols);
      const r    = Math.floor(i / Math.max(1, numCols));
      const risk = riskLevel(ep.risk_score);

      nodes.push({
        id: ep.id,
        type: "device",
        position: { x: startX + c * DEVICE_W, y: Y_SW + r * DEVICE_H },
        data: {
          ip: ep.ip_address,
          hostname: ep.hostname,
          os: ep.os_guess,
          risk,
          findingCount: ep.open_findings_count ?? 0,
          deviceType: resolveType(ep),
          device: ep,
        },
      });

      edges.push({
        id: `e-gw-${ep.id}`,
        source: primaryGwId,
        target: ep.id,
        style: {
          stroke: risk === "critical" ? "#ef4444"
            : risk === "high"     ? "#f97316"
            : "#cbd5e1",
          strokeWidth: risk === "critical" ? 2 : 1,
        },
        animated: risk === "critical",
      });
    });
  }

  return { nodes, edges };
}

// ─── Page ──────────────────────────────────────────────────────────

export default function NetworkTopology() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selectedDevice, setSelectedDevice] = useState<any>(null);
  const queryClient = useQueryClient();

  const { data: devices, isLoading } = useQuery({
    queryKey: ["devices"],
    queryFn: () => api.get("/api/devices?limit=200").then(r => r.data),
    refetchInterval: 30_000,
  });

  const { data: topoData, refetch: refetchTopo } = useQuery({
    queryKey: ["topology-links"],
    queryFn: () => api.get("/api/topology/links").then(r => r.data),
    staleTime: 60_000,
  });

  const { data: scanStatus, refetch: refetchStatus } = useQuery({
    queryKey: ["topology-status"],
    queryFn: () => api.get("/api/topology/status").then(r => r.data),
    refetchInterval: (data: any) => (data?.status === "running" ? 3000 : false),
  });

  // Refresh links when scan finishes
  useEffect(() => {
    if (scanStatus?.status === "done") {
      refetchTopo();
    }
  }, [scanStatus?.status]);

  const scanMutation = useMutation({
    mutationFn: () => api.post("/api/topology/scan"),
    onSuccess: () => {
      // Start polling status
      refetchStatus();
    },
  });

  const topoLinks: any[] = topoData?.links ?? [];
  const scanning = scanStatus?.status === "running" || scanMutation.isPending;

  useEffect(() => {
    if (devices?.items) {
      const { nodes: n, edges: e } = buildGraph(devices.items, topoLinks);
      setNodes(n);
      setEdges(e);
    }
  }, [devices, topoLinks]);

  const onNodeClick = useCallback((_: any, node: Node) => {
    if (node.data?.device) {
      setSelectedDevice(node.data.device);
    }
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400 text-sm">
        Loading network map…
      </div>
    );
  }

  return (
    <div className="flex h-full">
      <div className="flex-1 relative">

        {/* Scan topology button */}
        <div className="absolute top-4 right-4 z-10">
          <button
            onClick={() => scanMutation.mutate()}
            disabled={scanning}
            className="flex items-center gap-2 px-3 py-2 bg-white border border-gray-200 rounded-lg shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors disabled:opacity-60"
          >
            {scanning ? (
              <Loader2 className="w-4 h-4 animate-spin text-blue-500" />
            ) : (
              <ScanLine className="w-4 h-4 text-blue-500" />
            )}
            {scanning
              ? "Scanning LLDP… (35 s)"
              : topoLinks.length > 0
              ? `LLDP: ${topoLinks.length} confirmed`
              : "Scan LLDP Topology"}
          </button>
        </div>

        {/* Legend */}
        <div className="absolute top-4 left-4 z-10 bg-white border border-gray-200 rounded-lg px-3 py-2.5 shadow-sm space-y-3">

          <div>
            <div className="text-xs font-medium text-gray-500 mb-1.5">Risk level</div>
            {[
              { color: "bg-red-500",    label: "Critical" },
              { color: "bg-orange-500", label: "High" },
              { color: "bg-amber-500",  label: "Medium" },
              { color: "bg-blue-500",   label: "Low" },
              { color: "bg-green-500",  label: "Clean" },
            ].map(({ color, label }) => (
              <div key={label} className="flex items-center gap-1.5 text-xs text-gray-600 mb-1">
                <span className={`w-2 h-2 rounded-full ${color}`} />
                {label}
              </div>
            ))}
          </div>

          <div className="border-t border-gray-100 pt-2">
            <div className="text-xs text-gray-400 italic mb-2">
              {topoLinks.length > 0
                ? <>Device→switch: estimated.<br /><span className="text-green-600 not-italic">✓ = LLDP confirmed</span></>
                : <>Device→switch links estimated<br />by IP proximity. Click Scan to confirm.</>}
            </div>
            <div className="text-xs font-medium text-gray-500 mb-1.5">Node type</div>
            {[
              { icon: <Shield className="w-3 h-3 text-blue-400" />,   label: "Gateway / Router" },
              { icon: <Network className="w-3 h-3 text-blue-300" />,  label: "Switch" },
              { icon: <Wifi    className="w-3 h-3 text-blue-300" />,  label: "Access Point" },
              { icon: <Server  className="w-3 h-3 text-gray-500" />,  label: "Server" },
              { icon: <Monitor className="w-3 h-3 text-gray-500" />,  label: "Workstation" },
              { icon: <Printer className="w-3 h-3 text-gray-500" />,  label: "Printer" },
            ].map(({ icon, label }) => (
              <div key={label} className="flex items-center gap-1.5 text-xs text-gray-600 mb-1">
                {icon} {label}
              </div>
            ))}
          </div>
        </div>

        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          className="bg-gray-50"
        >
          <Background color="#e2e8f0" gap={20} />
          <Controls />
          <MiniMap
            nodeColor={node => {
              if (node.type === "gateway") return "#0f172a";
              if (node.type === "switch")  return "#1e3a5f";
              const risk = node.data?.risk;
              return risk === "critical" ? "#ef4444"
                : risk === "high"     ? "#f97316"
                : risk === "medium"   ? "#f59e0b"
                : risk === "low"      ? "#3b82f6"
                : "#22c55e";
            }}
            className="bg-white border border-gray-200 rounded-lg"
          />
        </ReactFlow>
      </div>

      {selectedDevice && (
        <FindingDetailPanel
          device={selectedDevice}
          onClose={() => setSelectedDevice(null)}
        />
      )}
    </div>
  );
}
