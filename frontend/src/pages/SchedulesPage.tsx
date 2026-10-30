import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { api } from "../utils/api";
import { formatDistanceToNow, format } from "date-fns";
import {
  Calendar, Plus, Play, Pause, Trash2,
  Clock, ChevronDown, ChevronUp, AlertTriangle
} from "lucide-react";
import toast from "react-hot-toast";

// ─── Cron presets ─────────────────────────────────────────────────
const CRON_PRESETS = [
  { label: "Every day at 2am",       value: "0 2 * * *" },
  { label: "Every Sunday at 2am",    value: "0 2 * * 0" },
  { label: "Every Monday at 7am",    value: "0 7 * * 1" },
  { label: "First of month at 3am",  value: "0 3 1 * *" },
  { label: "Every 6 hours",          value: "0 */6 * * *" },
  { label: "Custom…",                value: "custom" },
];

const SCAN_TYPES = [
  { value: "network_discovery", label: "Host Discovery" },
  { value: "port_scan",         label: "Port Scan" },
  { value: "vulnerability",     label: "Vulnerability Scan" },
  { value: "full_network",      label: "Full Network Scan" },
  { value: "compliance",        label: "Compliance Check" },
];

export default function SchedulesPage() {
  const [showCreate, setShowCreate] = useState(false);
  const queryClient = useQueryClient();

  const { data: schedules, isLoading } = useQuery({
    queryKey: ["schedules"],
    queryFn: () => api.get("/api/schedules").then(r => r.data),
    refetchInterval: 30_000,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/schedules/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["schedules"] });
      toast.success("Schedule deleted");
    },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      api.patch(`/api/schedules/${id}?is_active=${is_active}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["schedules"] }),
  });

  return (
    <div className="p-6 max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Scheduled Scans</h1>
          <p className="text-sm text-gray-500 mt-1">
            Automate recurring scans on a cron schedule
          </p>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="flex items-center gap-2 px-4 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          New schedule
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <CreateScheduleForm
          onSuccess={() => {
            setShowCreate(false);
            queryClient.invalidateQueries({ queryKey: ["schedules"] });
          }}
          onCancel={() => setShowCreate(false)}
        />
      )}

      {/* Schedule list */}
      {isLoading ? (
        <div className="text-sm text-gray-400 text-center py-12">Loading schedules…</div>
      ) : schedules?.length === 0 ? (
        <EmptyState onCreate={() => setShowCreate(true)} />
      ) : (
        <div className="space-y-3">
          {schedules?.map((schedule: any) => (
            <ScheduleCard
              key={schedule.id}
              schedule={schedule}
              onToggle={(active) => toggleMutation.mutate({ id: schedule.id, is_active: active })}
              onDelete={() => {
                if (confirm(`Delete schedule "${schedule.name}"?`)) {
                  deleteMutation.mutate(schedule.id);
                }
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Create form ──────────────────────────────────────────────────

function CreateScheduleForm({ onSuccess, onCancel }: { onSuccess: () => void; onCancel: () => void }) {
  const [cronPreset, setCronPreset] = useState("0 2 * * 0");
  const [isCustomCron, setIsCustomCron] = useState(false);

  const { register, handleSubmit, formState: { errors }, setValue, watch } = useForm({
    defaultValues: {
      name: "",
      scan_type: "port_scan",
      target: "192.168.1.0/24",
      cron_expression: "0 2 * * 0",
      options: {},
    },
  });

  const mutation = useMutation({
    mutationFn: (data: any) => api.post("/api/schedules", data),
    onSuccess,
    onError: (err: any) => toast.error(err.response?.data?.detail || "Failed to create schedule"),
  });

  const handlePresetChange = (value: string) => {
    if (value === "custom") {
      setIsCustomCron(true);
    } else {
      setIsCustomCron(false);
      setCronPreset(value);
      setValue("cron_expression", value);
    }
  };

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5 mb-6 shadow-sm">
      <h2 className="font-medium text-gray-900 mb-4">New Scheduled Scan</h2>
      <form onSubmit={handleSubmit(d => mutation.mutate(d))} className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          {/* Name */}
          <div className="col-span-2">
            <label className="block text-sm font-medium text-gray-700 mb-1.5">
              Schedule name
            </label>
            <input
              {...register("name", { required: "Name is required" })}
              placeholder="e.g. Weekly full network scan"
              className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            {errors.name && <p className="text-xs text-red-500 mt-1">{errors.name.message as string}</p>}
          </div>

          {/* Scan type */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1.5">Scan type</label>
            <select
              {...register("scan_type")}
              className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500"
            >
              {SCAN_TYPES.map(t => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
          </div>

          {/* Target */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1.5">Target</label>
            <input
              {...register("target", { required: "Target is required" })}
              placeholder="192.168.1.0/24"
              className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Schedule */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1.5">Frequency</label>
            <select
              value={isCustomCron ? "custom" : cronPreset}
              onChange={e => handlePresetChange(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500"
            >
              {CRON_PRESETS.map(p => (
                <option key={p.value} value={p.value}>{p.label}</option>
              ))}
            </select>
          </div>

          {/* Cron expression (custom or read-only preview) */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1.5">
              Cron expression
            </label>
            <input
              {...register("cron_expression", { required: "Cron expression is required" })}
              readOnly={!isCustomCron}
              placeholder="0 2 * * 0"
              className={`w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono focus:ring-2 focus:ring-blue-500 ${
                !isCustomCron ? "bg-gray-50 text-gray-500" : ""
              }`}
            />
            <p className="text-xs text-gray-400 mt-1">
              min hour day month weekday — <a href="https://crontab.guru" target="_blank" rel="noreferrer" className="text-blue-500 hover:underline">crontab.guru</a>
            </p>
          </div>
        </div>

        <div className="flex items-start gap-3 p-3 bg-amber-50 rounded-lg border border-amber-100">
          <AlertTriangle className="w-4 h-4 text-amber-500 mt-0.5 flex-shrink-0" />
          <p className="text-xs text-amber-700">
            Scheduled scans run automatically. Confirm the target range is a network you are authorized to scan.
          </p>
        </div>

        <div className="flex gap-3 pt-1">
          <button
            type="submit"
            disabled={mutation.isPending}
            className="px-4 py-2.5 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
          >
            {mutation.isPending ? "Creating…" : "Create schedule"}
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2.5 border border-gray-200 text-gray-600 rounded-lg text-sm hover:bg-gray-50 transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

// ─── Schedule card ─────────────────────────────────────────────────

function ScheduleCard({
  schedule,
  onToggle,
  onDelete,
}: {
  schedule: any;
  onToggle: (active: boolean) => void;
  onDelete: () => void;
}) {
  const typeLabel = SCAN_TYPES.find(t => t.value === schedule.scan_type)?.label || schedule.scan_type;

  return (
    <div className={`bg-white rounded-xl border transition-colors ${
      schedule.is_active ? "border-gray-200" : "border-gray-100 opacity-60"
    }`}>
      <div className="flex items-center justify-between px-5 py-4">
        <div className="flex items-center gap-4 flex-1 min-w-0">
          {/* Active indicator */}
          <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
            schedule.is_active ? "bg-green-500" : "bg-gray-300"
          }`} />

          <div className="min-w-0">
            <div className="font-medium text-gray-900 text-sm truncate">{schedule.name}</div>
            <div className="flex items-center gap-3 mt-0.5">
              <span className="text-xs text-gray-500">{typeLabel}</span>
              <span className="text-xs text-gray-400">·</span>
              <span className="text-xs font-mono text-gray-500">{schedule.target}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-5 flex-shrink-0 ml-4">
          {/* Cron + next run */}
          <div className="text-right hidden sm:block">
            <div className="flex items-center gap-1.5 text-xs text-gray-500 justify-end">
              <Clock className="w-3 h-3" />
              <span className="font-mono">{schedule.cron_expression}</span>
            </div>
            {schedule.next_run && (
              <div className="text-xs text-gray-400 mt-0.5">
                Next: {formatDistanceToNow(new Date(schedule.next_run), { addSuffix: true })}
              </div>
            )}
            {schedule.last_run && (
              <div className="text-xs text-gray-300 mt-0.5">
                Last: {format(new Date(schedule.last_run), "MMM d, HH:mm")}
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => onToggle(!schedule.is_active)}
              title={schedule.is_active ? "Pause schedule" : "Resume schedule"}
              className="p-1.5 rounded-md text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
            >
              {schedule.is_active
                ? <Pause className="w-4 h-4" />
                : <Play className="w-4 h-4" />}
            </button>
            <button
              onClick={onDelete}
              title="Delete schedule"
              className="p-1.5 rounded-md text-gray-400 hover:text-red-500 hover:bg-red-50 transition-colors"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Empty state ──────────────────────────────────────────────────

function EmptyState({ onCreate }: { onCreate: () => void }) {
  return (
    <div className="bg-white rounded-xl border border-dashed border-gray-200 p-12 text-center">
      <Calendar className="w-10 h-10 text-gray-300 mx-auto mb-3" />
      <div className="font-medium text-gray-700 mb-1">No scheduled scans</div>
      <p className="text-sm text-gray-400 mb-4 max-w-xs mx-auto">
        Automate your network monitoring with recurring scans on a cron schedule.
      </p>
      <button
        onClick={onCreate}
        className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors"
      >
        <Plus className="w-4 h-4" />
        Create your first schedule
      </button>
    </div>
  );
}
