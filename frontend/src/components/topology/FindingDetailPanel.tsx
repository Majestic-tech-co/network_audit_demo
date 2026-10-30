import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { X, Sparkles, RefreshCw, CheckCircle, User, AlertTriangle, Radio } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { api } from "../../utils/api";
import { formatDistanceToNow } from "date-fns";
import toast from "react-hot-toast";
import FindingSeverityBadge from "../shared/FindingSeverityBadge";

interface Props {
  device: any;
  onClose: () => void;
}

export default function FindingDetailPanel({ device, onClose }: Props) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const { data: findings, isLoading, isError } = useQuery({
    queryKey: ["device-findings", device.id],
    queryFn: () => api.get(`/api/devices/${device.id}/findings`).then(r => r.data.items ?? r.data),
  });

  const remediateMutation = useMutation({
    mutationFn: (findingId: string) =>
      api.post(`/api/findings/${findingId}/remediate`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["device-findings", device.id] });
      toast.success("AI remediation generated");
    },
    onError: () => toast.error("Failed to generate remediation"),
  });

  const resolveMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.patch(`/api/findings/${id}`, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["device-findings", device.id] });
      queryClient.invalidateQueries({ queryKey: ["open-findings"] });
      toast.success("Finding updated");
    },
  });

  return (
    <div className="w-96 flex-shrink-0 border-l border-gray-200 bg-white flex flex-col h-full">
      {/* Header */}
      <div className="flex items-start justify-between px-5 py-4 border-b border-gray-100">
        <div>
          <div className="font-semibold text-gray-900">{device.hostname || device.ip_address}</div>
          <div className="text-xs text-gray-400 mt-0.5">{device.ip_address} · {device.os_guess || "Unknown OS"}</div>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600 mt-0.5">
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Device summary */}
      <div className="px-5 py-3 bg-gray-50 border-b border-gray-100">
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div>
            <div className="text-gray-400">Device type</div>
            <div className="font-medium text-gray-700 capitalize">{device.device_type || "Unknown"}</div>
          </div>
          <div>
            <div className="text-gray-400">Risk score</div>
            <div className={`font-medium ${
              device.risk_score > 80 ? "text-red-600"
              : device.risk_score > 50 ? "text-orange-600"
              : device.risk_score > 20 ? "text-amber-600"
              : "text-green-600"
            }`}>{Math.round(device.risk_score)}/100</div>
          </div>
          <div>
            <div className="text-gray-400">First seen</div>
            <div className="font-medium text-gray-700">
              {device.first_seen ? formatDistanceToNow(new Date(device.first_seen)) + " ago" : "—"}
            </div>
          </div>
          <div>
            <div className="text-gray-400">Open ports</div>
            <div className="font-medium text-gray-700">{device.ports?.length ?? 0}</div>
          </div>
          <div className="col-span-2 pt-1">
            <button
              onClick={() => navigate(`/capture?host=${device.ip_address}`)}
              className="flex items-center gap-1.5 text-xs text-purple-600 hover:text-purple-700 font-medium"
            >
              <Radio className="w-3 h-3" />
              Capture traffic from this device
            </button>
          </div>
        </div>
      </div>

      {/* Findings list */}
      <div className="flex-1 overflow-y-auto">
        {isLoading && (
          <div className="p-5 text-sm text-gray-400 text-center">Loading findings…</div>
        )}

        {isError && (
          <div className="p-5 text-center text-sm text-red-500">
            Failed to load findings. Check the API logs.
          </div>
        )}

        {!isLoading && !isError && findings?.length === 0 && (
          <div className="p-5 text-center">
            <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
            <div className="text-sm text-gray-500">No findings for this device</div>
          </div>
        )}

        {findings?.map((finding: any) => (
          <FindingCard
            key={finding.id}
            finding={finding}
            onRemediate={() => remediateMutation.mutate(finding.id)}
            onResolve={(status: string) => resolveMutation.mutate({ id: finding.id, status })}
            isGenerating={remediateMutation.isPending}
          />
        ))}
      </div>
    </div>
  );
}

function FindingCard({ finding, onRemediate, onResolve, isGenerating }: any) {
  const isResolved = finding.status === "resolved" || finding.status === "false_positive";

  return (
    <div className={`border-b border-gray-100 px-5 py-4 ${isResolved ? "opacity-50" : ""}`}>
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="flex-1">
          <div className="text-sm font-medium text-gray-800 leading-tight">{finding.title}</div>
          <div className="text-xs text-gray-400 mt-1">
            {formatDistanceToNow(new Date(finding.created_at))} ago
          </div>
        </div>
        <FindingSeverityBadge severity={finding.severity} />
      </div>

      <p className="text-xs text-gray-500 leading-relaxed mb-3">{finding.description}</p>

      {/* Virus-specific detail */}
      {finding.virus_name && (
        <div className="bg-red-50 rounded-md px-3 py-2 mb-3 text-xs">
          <div className="font-medium text-red-700">{finding.virus_name}</div>
          {finding.file_path && <div className="text-red-500 font-mono mt-0.5 truncate">{finding.file_path}</div>}
          {finding.file_hash && <div className="text-red-400 font-mono truncate">{finding.file_hash.slice(0, 16)}…</div>}
        </div>
      )}

      {/* AI Remediation */}
      {finding.ai_remediation ? (
        <div className="bg-blue-50 rounded-md p-3 mb-3">
          <div className="flex items-center gap-1.5 text-xs font-medium text-blue-700 mb-2">
            <Sparkles className="w-3 h-3" />
            AI Remediation
            <span className="text-blue-400 font-normal ml-auto">via {finding.ai_provider_used}</span>
          </div>
          <div className="text-xs text-blue-900 leading-relaxed whitespace-pre-wrap max-h-48 overflow-y-auto">
            {finding.ai_remediation}
          </div>
          <button
            onClick={onRemediate}
            disabled={isGenerating}
            className="flex items-center gap-1 text-xs text-blue-500 hover:text-blue-700 mt-2"
          >
            <RefreshCw className="w-3 h-3" />
            Regenerate
          </button>
        </div>
      ) : (
        <button
          onClick={onRemediate}
          disabled={isGenerating}
          className="flex items-center gap-1.5 text-xs text-blue-600 hover:text-blue-700 mb-3 disabled:opacity-50"
        >
          <Sparkles className="w-3 h-3" />
          {isGenerating ? "Generating…" : "Generate AI remediation"}
        </button>
      )}

      {/* Actions */}
      {!isResolved && (
        <div className="flex gap-2">
          <button
            onClick={() => onResolve("resolved")}
            className="flex items-center gap-1 text-xs px-2.5 py-1.5 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors"
          >
            <CheckCircle className="w-3 h-3" />
            Mark resolved
          </button>
          <button
            onClick={() => onResolve("in_progress")}
            className="flex items-center gap-1 text-xs px-2.5 py-1.5 border border-gray-200 text-gray-600 rounded-md hover:bg-gray-50 transition-colors"
          >
            <User className="w-3 h-3" />
            In progress
          </button>
          <button
            onClick={() => onResolve("false_positive")}
            className="text-xs px-2.5 py-1.5 text-gray-400 hover:text-gray-600"
          >
            False positive
          </button>
        </div>
      )}

      {isResolved && (
        <div className="flex items-center gap-1.5 text-xs text-green-600">
          <CheckCircle className="w-3 h-3" />
          {finding.status === "resolved" ? "Resolved" : "Marked as false positive"}
        </div>
      )}
    </div>
  );
}
