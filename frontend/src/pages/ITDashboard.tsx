import { useQuery } from "@tanstack/react-query";
import {
  Shield, AlertTriangle, CheckCircle, Monitor,
  Wifi, Bug, Activity, ChevronRight, Plus, Download
} from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../utils/api";
import toast from "react-hot-toast";
import { formatDistanceToNow } from "date-fns";
import ScanLaunchModal from "../components/dashboard/ScanLaunchModal";
import OnboardingChecklist from "../components/dashboard/OnboardingChecklist";
import { useState } from "react";
import FindingSeverityBadge from "../components/shared/FindingSeverityBadge";

export default function ITDashboard() {
  const [showScanModal, setShowScanModal] = useState(false);

  const { data: stats } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: () => api.get("/api/dashboard/stats").then(r => r.data),
    refetchInterval: 15_000,
  });

  const { data: recentScans } = useQuery({
    queryKey: ["recent-scans"],
    queryFn: () => api.get("/api/scans?limit=5").then(r => r.data),
    refetchInterval: 10_000,
  });

  const { data: openFindings } = useQuery({
    queryKey: ["open-findings"],
    queryFn: () => api.get("/api/findings?status=open&limit=8").then(r => r.data),
    refetchInterval: 15_000,
  });

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Network Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">
            {stats?.last_scan
              ? `Last scan ${formatDistanceToNow(new Date(stats.last_scan))} ago`
              : "No scans yet"}
          </p>
        </div>
        <button
          onClick={() => setShowScanModal(true)}
          className="flex items-center gap-2 px-4 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium text-sm"
        >
          <Plus className="w-4 h-4" />
          New Scan
        </button>
      </div>

      {/* Onboarding checklist — shows until all steps complete */}
      <OnboardingChecklist />

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={<Monitor className="w-5 h-5 text-blue-500" />}
          label="Devices Discovered"
          value={stats?.total_devices ?? "—"}
          bg="bg-blue-50"
        />
        <StatCard
          icon={<AlertTriangle className="w-5 h-5 text-red-500" />}
          label="Critical Findings"
          value={stats?.critical_findings ?? "—"}
          bg="bg-red-50"
          highlight={stats?.critical_findings > 0}
        />
        <StatCard
          icon={<Bug className="w-5 h-5 text-orange-500" />}
          label="Virus Threats"
          value={stats?.virus_threats ?? "—"}
          bg="bg-orange-50"
          highlight={stats?.virus_threats > 0}
        />
        <StatCard
          icon={<CheckCircle className="w-5 h-5 text-green-500" />}
          label="Resolved (30d)"
          value={stats?.resolved_30d ?? "—"}
          bg="bg-green-50"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-gray-400" />
              <h2 className="font-medium text-gray-900">Recent Scans</h2>
            </div>
            <Link to="/topology" className="text-xs text-blue-600 hover:text-blue-700 flex items-center gap-1">
              View topology <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="divide-y divide-gray-50">
            {recentScans?.items?.length === 0 && (
              <div className="px-5 py-8 text-center text-sm text-gray-400">
                No scans yet. Start one above.
              </div>
            )}
            {recentScans?.items?.map((scan: any) => (
              <ScanRow key={scan.id} scan={scan} />
            ))}
          </div>
        </div>

        {/* Open Findings */}
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-gray-400" />
              <h2 className="font-medium text-gray-900">Open Findings</h2>
            </div>
            <Link to="/findings" className="text-xs text-blue-600 hover:text-blue-700 flex items-center gap-1">
              View all <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="divide-y divide-gray-50">
            {openFindings?.items?.length === 0 && (
              <div className="px-5 py-8 text-center text-sm text-gray-400">
                <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
                No open findings. Network looks clean.
              </div>
            )}
            {openFindings?.items?.map((finding: any) => (
              <FindingRow key={finding.id} finding={finding} />
            ))}
          </div>
        </div>
      </div>

      {showScanModal && <ScanLaunchModal onClose={() => setShowScanModal(false)} />}
    </div>
  );
}

function StatCard({ icon, label, value, bg, highlight = false }: any) {
  return (
    <div className={`rounded-xl p-4 ${bg} ${highlight ? "ring-2 ring-red-200" : ""}`}>
      <div className="flex items-center justify-between mb-2">
        {icon}
        {highlight && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />}
      </div>
      <div className="text-2xl font-semibold text-gray-900">{value}</div>
      <div className="text-xs text-gray-500 mt-0.5">{label}</div>
    </div>
  );
}

function ScanRow({ scan }: { scan: any }) {
  const statusColors: Record<string, string> = {
    completed: "text-green-600 bg-green-50",
    running: "text-blue-600 bg-blue-50",
    failed: "text-red-600 bg-red-50",
    pending: "text-gray-600 bg-gray-100",
  };
  const typeLabels: Record<string, string> = {
    full_network: "Full Network",
    port_scan: "Port Scan",
    vulnerability: "Vulnerability",
    virus: "Virus Scan",
    full_device: "Device Scan",
  };

  const handleDownload = async (format: "pdf" | "json") => {
    try {
      const auth = JSON.parse(localStorage.getItem("netaudit-auth") || "{}");
      const token = auth?.state?.accessToken;
      const res = await fetch(`/api/scans/${scan.id}/report.${format}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Download failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `netaudit-report-${scan.target?.replace(/\//g, "-")}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      toast.error("Failed to download report");
    }
  };

  return (
    <div className="flex items-center justify-between px-5 py-3">
      <div>
        <div className="text-sm font-medium text-gray-800">
          {typeLabels[scan.scan_type] || scan.scan_type}
        </div>
        <div className="text-xs text-gray-400 mt-0.5">
          {scan.target} · {formatDistanceToNow(new Date(scan.created_at))} ago
        </div>
      </div>
      <div className="flex items-center gap-3">
        {scan.findings_count > 0 && (
          <span className="text-xs text-red-600 font-medium">{scan.findings_count} findings</span>
        )}
        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${statusColors[scan.status] || statusColors.pending}`}>
          {scan.status}
        </span>
        {scan.status === "completed" && (
          <button
            onClick={() => handleDownload("pdf")}
            className="text-gray-400 hover:text-blue-600 transition-colors"
            title="Download PDF report"
          >
            <Download className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </div>
  );
}

function FindingRow({ finding }: { finding: any }) {
  return (
    <Link to={`/findings?id=${finding.id}`} className="flex items-start justify-between px-5 py-3 hover:bg-gray-50 transition-colors">
      <div className="flex-1 min-w-0 mr-3">
        <div className="text-sm font-medium text-gray-800 truncate">{finding.title}</div>
        <div className="text-xs text-gray-400 mt-0.5">
          {finding.device?.ip_address} · {formatDistanceToNow(new Date(finding.created_at))} ago
        </div>
      </div>
      <FindingSeverityBadge severity={finding.severity} />
    </Link>
  );
}
