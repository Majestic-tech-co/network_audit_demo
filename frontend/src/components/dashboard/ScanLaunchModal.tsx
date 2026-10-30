// ─── ScanLaunchModal.tsx ───────────────────────────────────────────
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../utils/api";
import { X, AlertTriangle } from "lucide-react";
import toast from "react-hot-toast";

const SCAN_TYPES = [
  { value: "network_discovery", label: "Host Discovery", desc: "Find all devices on the network", fast: true },
  { value: "port_scan", label: "Port Scan", desc: "Discover open ports and services", fast: false },
  { value: "vulnerability", label: "Vulnerability Scan", desc: "Deep CVE and misconfiguration check", fast: false },
  { value: "full_network", label: "Full Network Scan", desc: "Everything — takes 30-60 min", fast: false },
  { value: "virus", label: "Network Virus Sweep", desc: "Check agent-connected devices for malware", fast: false },
];

interface Props { onClose: () => void; }

export default function ScanLaunchModal({ onClose }: Props) {
  const [scanType, setScanType] = useState("port_scan");
  const [target, setTarget] = useState("192.168.1.0/24");
  const [authorized, setAuthorized] = useState(false);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () => api.post("/api/scans", { scan_type: scanType, target }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["recent-scans"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
      toast.success("Scan started");
      onClose();
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || "Failed to start scan"),
  });

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 px-4">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-md">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
          <h2 className="font-semibold text-gray-900">New Scan</h2>
          <button onClick={onClose}><X className="w-5 h-5 text-gray-400 hover:text-gray-600" /></button>
        </div>

        <div className="p-5 space-y-4">
          {/* Scan type */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Scan type</label>
            <div className="space-y-2">
              {SCAN_TYPES.map(type => (
                <label key={type.value} className="flex items-start gap-3 cursor-pointer group">
                  <input type="radio" name="scan_type" value={type.value}
                    checked={scanType === type.value}
                    onChange={() => setScanType(type.value)}
                    className="mt-0.5" />
                  <div>
                    <div className="text-sm font-medium text-gray-800 flex items-center gap-2">
                      {type.label}
                      {type.fast && <span className="text-xs bg-green-100 text-green-700 px-1.5 py-0.5 rounded-full">Fast</span>}
                    </div>
                    <div className="text-xs text-gray-400">{type.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Target */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1.5">Target (CIDR or IP)</label>
            <input value={target} onChange={e => setTarget(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500"
              placeholder="192.168.1.0/24" />
            <p className="text-xs text-gray-400 mt-1">Private IP ranges only (RFC 1918)</p>
          </div>

          {/* Authorization checkbox */}
          <div className="flex items-start gap-3 p-3 bg-amber-50 rounded-lg border border-amber-200">
            <input type="checkbox" id="auth-confirm" checked={authorized}
              onChange={e => setAuthorized(e.target.checked)} className="mt-0.5" />
            <label htmlFor="auth-confirm" className="text-xs text-amber-800 cursor-pointer leading-relaxed">
              <span className="font-semibold flex items-center gap-1 mb-0.5">
                <AlertTriangle className="w-3 h-3" /> Authorization required
              </span>
              I confirm I own this network or have written authorization to scan it. Unauthorized scanning may be illegal.
            </label>
          </div>
        </div>

        <div className="flex gap-3 px-5 pb-5">
          <button onClick={() => mutation.mutate()} disabled={!authorized || mutation.isPending || !target}
            className="flex-1 py-2.5 bg-blue-600 text-white rounded-lg font-medium text-sm hover:bg-blue-700 disabled:opacity-50 transition-colors">
            {mutation.isPending ? "Starting…" : "Start scan"}
          </button>
          <button onClick={onClose} className="px-4 py-2.5 border border-gray-200 rounded-lg text-sm text-gray-600 hover:bg-gray-50">
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
