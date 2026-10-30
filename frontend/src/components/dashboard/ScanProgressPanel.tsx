import { useEffect } from "react";
import { CheckCircle, XCircle, Loader, X, Monitor, AlertTriangle } from "lucide-react";
import { useScanProgressStore, ScanProgress } from "../../store/scanProgressStore";
import { useQueryClient } from "@tanstack/react-query";

export default function ScanProgressPanel() {
  const { activeScans, clearScan } = useScanProgressStore();
  const queryClient = useQueryClient();
  const scans = Object.values(activeScans);

  // Refresh dashboard data when a scan completes
  useEffect(() => {
    const completed = scans.filter(s => s.status === "complete");
    if (completed.length > 0) {
      queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
      queryClient.invalidateQueries({ queryKey: ["recent-scans"] });
      queryClient.invalidateQueries({ queryKey: ["open-findings"] });
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    }
  }, [scans.filter(s => s.status === "complete").length]);

  if (scans.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-80">
      {scans.map(scan => (
        <ScanCard key={scan.scanId} scan={scan} onDismiss={() => clearScan(scan.scanId)} />
      ))}
    </div>
  );
}

function ScanCard({ scan, onDismiss }: { scan: ScanProgress; onDismiss: () => void }) {
  const isComplete = scan.status === "complete";
  const isFailed = scan.status === "failed";
  const isRunning = scan.status === "running";

  // Auto-dismiss completed/failed scans after 8 seconds
  useEffect(() => {
    if (isComplete || isFailed) {
      const t = setTimeout(onDismiss, 8_000);
      return () => clearTimeout(t);
    }
  }, [isComplete, isFailed]);

  return (
    <div className={`bg-white rounded-xl border shadow-lg overflow-hidden transition-all ${
      isComplete ? "border-green-200" :
      isFailed ? "border-red-200" :
      "border-gray-200"
    }`}>
      {/* Header */}
      <div className={`flex items-center justify-between px-4 py-3 ${
        isComplete ? "bg-green-50" :
        isFailed ? "bg-red-50" :
        "bg-blue-50"
      }`}>
        <div className="flex items-center gap-2">
          {isRunning && <Loader className="w-4 h-4 text-blue-500 animate-spin" />}
          {isComplete && <CheckCircle className="w-4 h-4 text-green-500" />}
          {isFailed && <XCircle className="w-4 h-4 text-red-500" />}
          <span className={`text-sm font-medium ${
            isComplete ? "text-green-800" :
            isFailed ? "text-red-800" :
            "text-blue-800"
          }`}>
            {isRunning ? "Scan running…" : isComplete ? "Scan complete" : "Scan failed"}
          </span>
        </div>
        {(isComplete || isFailed) && (
          <button onClick={onDismiss} className="text-gray-400 hover:text-gray-600">
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-gray-100">
        <div
          className={`h-full transition-all duration-700 ease-out ${
            isComplete ? "bg-green-500" :
            isFailed ? "bg-red-500" :
            "bg-blue-500"
          }`}
          style={{ width: `${scan.percent}%` }}
        />
      </div>

      {/* Body */}
      <div className="px-4 py-3">
        <p className="text-xs text-gray-600 leading-relaxed">{scan.message}</p>

        {isComplete && (
          <div className="flex items-center gap-4 mt-2">
            {scan.hostsFound !== undefined && (
              <div className="flex items-center gap-1 text-xs text-gray-500">
                <Monitor className="w-3 h-3" />
                {scan.hostsFound} hosts
              </div>
            )}
            {scan.findingsCount !== undefined && scan.findingsCount > 0 && (
              <div className="flex items-center gap-1 text-xs text-red-500">
                <AlertTriangle className="w-3 h-3" />
                {scan.findingsCount} findings
              </div>
            )}
          </div>
        )}

        {/* Percent badge when running */}
        {isRunning && (
          <div className="text-right mt-1">
            <span className="text-xs font-medium text-blue-600">{scan.percent}%</span>
          </div>
        )}
      </div>
    </div>
  );
}
