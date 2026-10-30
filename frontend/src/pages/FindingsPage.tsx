// ─── FindingsPage.tsx ──────────────────────────────────────────────
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../utils/api";
import { formatDistanceToNow } from "date-fns";
import { Sparkles, CheckCircle, Download } from "lucide-react";
import FindingSeverityBadge from "../components/shared/FindingSeverityBadge";
import toast from "react-hot-toast";

export default function FindingsPage() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(1);
  const queryClient = useQueryClient();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["findings", status, severity, page],
    queryFn: () => api.get(`/api/findings?page=${page}&limit=25${status ? `&status=${status}` : ""}${severity ? `&severity=${severity}` : ""}`).then(r => r.data),
    refetchInterval: 15_000,
  });

  const resolveMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) => api.patch(`/api/findings/${id}`, { status }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["findings"] }); toast.success("Updated"); },
  });

  const remediateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/findings/${id}/remediate`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["findings"] }); toast.success("AI remediation queued"); },
  });

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-semibold text-gray-900">Findings</h1>
        <div className="flex items-center gap-3">
          <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }}
            className="border border-gray-300 rounded-lg px-3 py-2 text-sm">
            <option value="">All severities</option>
            {["critical","high","medium","low","info"].map(s => <option key={s} value={s} className="capitalize">{s}</option>)}
          </select>
          <select value={status} onChange={e => { setStatus(e.target.value); setPage(1); }}
            className="border border-gray-300 rounded-lg px-3 py-2 text-sm">
            <option value="">All statuses</option>
            {["open","acknowledged","in_progress","resolved","false_positive"].map(s => <option key={s} value={s}>{s.replace("_"," ")}</option>)}
          </select>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-sm text-gray-400">Loading findings…</div>
        ) : isError ? (
          <div className="p-8 text-center text-sm text-red-500">Failed to load findings. Check the API logs.</div>
        ) : data?.items?.length === 0 ? (
          <div className="p-8 text-center text-sm text-gray-400">No findings match your filters.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-100">
              <tr>
                {["Severity","Title","Device","Type","Status","Age","Actions"].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {data?.items?.map((f: any) => (
                <tr key={f.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3"><FindingSeverityBadge severity={f.severity} /></td>
                  <td className="px-4 py-3 font-medium text-gray-800 max-w-xs truncate">{f.title}</td>
                  <td className="px-4 py-3 text-gray-500 font-mono text-xs">{f.device?.ip_address || "—"}</td>
                  <td className="px-4 py-3 text-gray-500 text-xs">{f.finding_type.replace("_"," ")}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${
                      f.status === "resolved" ? "bg-green-100 text-green-700"
                      : f.status === "open" ? "bg-red-100 text-red-700"
                      : "bg-gray-100 text-gray-600"}`}>
                      {f.status.replace("_"," ")}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-xs whitespace-nowrap">
                    {formatDistanceToNow(new Date(f.created_at))} ago
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2">
                      {!f.ai_remediation && (
                        <button onClick={() => remediateMutation.mutate(f.id)}
                          className="text-xs text-blue-600 hover:text-blue-700 flex items-center gap-1">
                          <Sparkles className="w-3 h-3" /> AI fix
                        </button>
                      )}
                      {f.status !== "resolved" && (
                        <button onClick={() => resolveMutation.mutate({ id: f.id, status: "resolved" })}
                          className="text-xs text-green-600 hover:text-green-700 flex items-center gap-1">
                          <CheckCircle className="w-3 h-3" /> Resolve
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {data?.total > 25 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-100">
            <span className="text-xs text-gray-400">{data.total} total findings</span>
            <div className="flex gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="text-xs px-3 py-1.5 border border-gray-200 rounded-lg disabled:opacity-40">Previous</button>
              <button onClick={() => setPage(p => p + 1)} disabled={page * 25 >= data.total}
                className="text-xs px-3 py-1.5 border border-gray-200 rounded-lg disabled:opacity-40">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
