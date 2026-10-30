import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Shield, Scan, AlertTriangle, CheckCircle,
  Bug, Wifi, LogOut, Clock, ChevronDown, ChevronUp
} from "lucide-react";
import { api } from "../utils/api";
import { useAuthStore } from "../store/authStore";
import { formatDistanceToNow } from "date-fns";
import toast from "react-hot-toast";

export default function UserDashboard() {
  const { user, logout } = useAuthStore();
  const queryClient = useQueryClient();
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const { data: myDevice, isLoading: deviceLoading } = useQuery({
    queryKey: ["my-device"],
    queryFn: () => api.get("/api/user/device").then(r => r.data),
    refetchInterval: 10_000,
  });

  const { data: myFindings } = useQuery({
    queryKey: ["my-findings"],
    queryFn: () => api.get("/api/user/findings").then(r => r.data),
    refetchInterval: 15_000,
  });

  const scanMutation = useMutation({
    mutationFn: (scanType: string) =>
      api.post("/api/user/scan", { scan_type: scanType }),
    onSuccess: () => {
      toast.success("Scan started! This may take a few minutes.");
      queryClient.invalidateQueries({ queryKey: ["my-device"] });
    },
    onError: () => toast.error("Failed to start scan. Is your agent running?"),
  });

  const openFindings = myFindings?.filter((f: any) =>
    ["open", "acknowledged", "in_progress"].includes(f.status)
  ) ?? [];

  const resolvedFindings = myFindings?.filter((f: any) =>
    f.status === "resolved"
  ) ?? [];

  const riskLevel = openFindings.some((f: any) => f.severity === "critical")
    ? "critical"
    : openFindings.some((f: any) => f.severity === "high")
    ? "high"
    : openFindings.some((f: any) => ["medium", "low"].includes(f.severity))
    ? "medium"
    : "clean";

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 px-6 py-4">
        <div className="max-w-2xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-600" />
            <span className="font-semibold text-gray-900">NetAudit</span>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-500">{user?.email}</span>
            <button
              onClick={logout}
              className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-700"
            >
              <LogOut className="w-4 h-4" />
              Sign out
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-2xl mx-auto px-6 py-8 space-y-6">
        {/* Risk Status Card */}
        <RiskStatusCard riskLevel={riskLevel} deviceInfo={myDevice} />

        {/* Scan Actions */}
        <div className="bg-white rounded-xl border border-gray-200 p-5">
          <h2 className="font-medium text-gray-900 mb-4">Scan My Computer</h2>
          <div className="grid grid-cols-2 gap-3">
            <ScanButton
              icon={<Bug className="w-4 h-4" />}
              label="Quick Virus Scan"
              description="Common locations · ~2 min"
              onClick={() => scanMutation.mutate("virus_quick")}
              loading={scanMutation.isPending}
              color="orange"
            />
            <ScanButton
              icon={<Shield className="w-4 h-4" />}
              label="Full Virus Scan"
              description="Entire device · 10–30 min"
              onClick={() => scanMutation.mutate("virus_full")}
              loading={scanMutation.isPending}
              color="red"
            />
            <ScanButton
              icon={<Wifi className="w-4 h-4" />}
              label="Network Check"
              description="Open ports & connections"
              onClick={() => scanMutation.mutate("network_device")}
              loading={scanMutation.isPending}
              color="blue"
            />
            <ScanButton
              icon={<Scan className="w-4 h-4" />}
              label="Full Device Scan"
              description="Everything · ~15 min"
              onClick={() => scanMutation.mutate("full_device")}
              loading={scanMutation.isPending}
              color="purple"
            />
          </div>

          {/* Agent status indicator */}
          <div className={`mt-4 flex items-center gap-2 text-xs px-3 py-2 rounded-lg ${
            myDevice?.agent_connected
              ? "bg-green-50 text-green-700"
              : "bg-amber-50 text-amber-700"
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${
              myDevice?.agent_connected ? "bg-green-500" : "bg-amber-400 animate-pulse"
            }`} />
            {myDevice?.agent_connected
              ? `Agent connected · last seen ${formatDistanceToNow(new Date(myDevice.last_agent_checkin))} ago`
              : "Agent offline — install the NetAudit agent to enable scanning"
            }
          </div>
        </div>

        {/* Issues Found */}
        {openFindings.length > 0 && (
          <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-100">
              <h2 className="font-medium text-gray-900">
                Issues Found
                <span className="ml-2 text-xs bg-red-100 text-red-700 px-2 py-0.5 rounded-full">
                  {openFindings.length}
                </span>
              </h2>
              <p className="text-xs text-gray-500 mt-0.5">Your IT team has been notified and is working on fixes.</p>
            </div>
            <div className="divide-y divide-gray-50">
              {openFindings.map((finding: any) => (
                <UserFindingRow
                  key={finding.id}
                  finding={finding}
                  expanded={expandedFinding === finding.id}
                  onToggle={() => setExpandedFinding(
                    expandedFinding === finding.id ? null : finding.id
                  )}
                />
              ))}
            </div>
          </div>
        )}

        {/* All Clear */}
        {!deviceLoading && openFindings.length === 0 && (
          <div className="bg-green-50 rounded-xl border border-green-200 p-6 text-center">
            <CheckCircle className="w-10 h-10 text-green-500 mx-auto mb-2" />
            <div className="font-medium text-green-800">Your computer looks clean</div>
            <div className="text-sm text-green-600 mt-1">
              {resolvedFindings.length > 0
                ? `${resolvedFindings.length} issue${resolvedFindings.length > 1 ? "s" : ""} previously resolved`
                : "No issues detected in your last scan"}
            </div>
          </div>
        )}

        {/* Agent Install Instructions */}
        {!myDevice?.agent_connected && (
          <AgentInstallCard />
        )}
      </main>
    </div>
  );
}

function RiskStatusCard({ riskLevel, deviceInfo }: any) {
  const configs: Record<string, { bg: string; border: string; icon: React.ReactNode; title: string; sub: string }> = {
    clean:    { bg: "bg-green-50",  border: "border-green-200",  icon: <CheckCircle className="w-8 h-8 text-green-500" />,  title: "Your computer is protected",  sub: "No threats detected" },
    medium:   { bg: "bg-amber-50",  border: "border-amber-200",  icon: <AlertTriangle className="w-8 h-8 text-amber-500" />, title: "Minor issues detected",        sub: "Low-risk items found — IT team has been notified" },
    high:     { bg: "bg-orange-50", border: "border-orange-200", icon: <AlertTriangle className="w-8 h-8 text-orange-500" />,title: "Issues require attention",      sub: "IT team is reviewing your device" },
    critical: { bg: "bg-red-50",    border: "border-red-200",    icon: <Shield className="w-8 h-8 text-red-500" />,         title: "Critical threat detected",      sub: "IT team has been alerted and will contact you" },
  };
  const config = configs[riskLevel] ?? {
    bg: "bg-gray-50", border: "border-gray-200",
    icon: <Shield className="w-8 h-8 text-gray-400" />,
    title: "Run a scan to check your device",
    sub: "No scan data available yet",
  };

  return (
    <div className={`rounded-xl border p-5 ${config.bg} ${config.border}`}>
      <div className="flex items-center gap-4">
        {config.icon}
        <div>
          <div className="font-semibold text-gray-900">{config.title}</div>
          <div className="text-sm text-gray-600 mt-0.5">{config.sub}</div>
        </div>
      </div>
      {deviceInfo?.last_scan && (
        <div className="flex items-center gap-1.5 mt-3 text-xs text-gray-500">
          <Clock className="w-3 h-3" />
          Last scanned {formatDistanceToNow(new Date(deviceInfo.last_scan))} ago
        </div>
      )}
    </div>
  );
}

function ScanButton({ icon, label, description, onClick, loading, color }: any) {
  const colors: Record<string, string> = {
    orange: "hover:bg-orange-50 hover:border-orange-200 text-orange-600",
    red: "hover:bg-red-50 hover:border-red-200 text-red-600",
    blue: "hover:bg-blue-50 hover:border-blue-200 text-blue-600",
    purple: "hover:bg-purple-50 hover:border-purple-200 text-purple-600",
  };

  return (
    <button
      onClick={onClick}
      disabled={loading}
      className={`flex flex-col items-start p-3.5 border border-gray-200 rounded-lg transition-colors text-left disabled:opacity-50 ${colors[color]}`}
    >
      <div className="mb-2">{icon}</div>
      <div className="text-sm font-medium text-gray-800">{label}</div>
      <div className="text-xs text-gray-400 mt-0.5">{description}</div>
    </button>
  );
}

function UserFindingRow({ finding, expanded, onToggle }: any) {
  const severityColors: Record<string, string> = {
    critical: "text-red-700 bg-red-100",
    high: "text-orange-700 bg-orange-100",
    medium: "text-amber-700 bg-amber-100",
    low: "text-blue-700 bg-blue-100",
  };

  return (
    <div>
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-gray-50 transition-colors text-left"
      >
        <div className="flex items-center gap-3">
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${severityColors[finding.severity] || "text-gray-600 bg-gray-100"}`}>
            {finding.severity}
          </span>
          <span className="text-sm text-gray-800">{finding.title}</span>
        </div>
        {expanded ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
      </button>
      {expanded && (
        <div className="px-5 pb-4 space-y-3">
          <p className="text-sm text-gray-600">{finding.description}</p>
          {finding.ai_remediation && (
            <div className="bg-blue-50 rounded-lg p-4">
              <div className="text-xs font-medium text-blue-700 mb-2">What your IT team is doing</div>
              <div className="text-sm text-blue-900 whitespace-pre-wrap leading-relaxed">
                {finding.ai_remediation}
              </div>
            </div>
          )}
          <div className="text-xs text-gray-400">
            Status: <span className="font-medium capitalize">{finding.status.replace("_", " ")}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function AgentInstallCard() {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5">
      <h3 className="font-medium text-gray-900 mb-2">Install the NetAudit Agent</h3>
      <p className="text-sm text-gray-500 mb-4">
        The agent runs quietly in the background and allows IT to run virus scans and device checks on your computer.
      </p>
      <div className="bg-gray-900 rounded-lg p-3 font-mono text-xs text-green-400">
        curl -sSL https://your-dashboard/install.sh | sh
      </div>
      <p className="text-xs text-gray-400 mt-2">Ask your IT team for the correct install link for your company.</p>
    </div>
  );
}
