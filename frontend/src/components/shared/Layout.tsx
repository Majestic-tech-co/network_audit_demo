// ─── src/components/shared/Layout.tsx ─────────────────────────────
import { Outlet, NavLink } from "react-router-dom";
import {
  Shield, LayoutDashboard, Network, AlertTriangle,
  Users, Settings, LogOut, Calendar, Radio
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useAuthStore } from "../../store/authStore";
import { useWebSocket } from "../../hooks/useWebSocket";
import { useScanProgressStore } from "../../store/scanProgressStore";
import ScanProgressPanel from "../dashboard/ScanProgressPanel";
import { api } from "../../utils/api";

const navItems = [
  { to: "/dashboard", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/topology",  icon: Network,         label: "Network Map" },
  { to: "/findings",  icon: AlertTriangle,   label: "Findings" },
  { to: "/schedules", icon: Calendar,        label: "Schedules" },
  { to: "/capture",   icon: Radio,           label: "Packet Capture" },
  { to: "/users",     icon: Users,           label: "Users" },
  { to: "/settings",  icon: Settings,        label: "Settings" },
];

export default function Layout() {
  const { user, logout } = useAuthStore();
  const { startScan, setScanProgress, completeScan, failScan } = useScanProgressStore();

  const { data: orgProfile } = useQuery({
    queryKey: ["org-profile"],
    queryFn: () => api.get("/api/settings/organization").then(r => r.data),
    staleTime: 5 * 60 * 1000,
  });

  // Connect WebSocket and handle incoming scan events
  useWebSocket((event) => {
    switch (event.event) {
      case "scan_started":
        startScan(event.scan_id, event.payload.message);
        break;
      case "scan_progress":
        setScanProgress(event.scan_id, {
          percent: event.payload.percent,
          message: event.payload.message,
          hostsFound: event.payload.hosts_found,
        });
        break;
      case "scan_complete":
        completeScan(event.scan_id, {
          hostsFound: event.payload.hosts_discovered,
          findingsCount: event.payload.findings_count,
        });
        break;
      case "scan_failed":
        failScan(event.scan_id, event.payload.message);
        break;
    }
  });

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="w-56 bg-white border-r border-gray-200 flex flex-col">
        <div className="flex items-center gap-2.5 px-5 py-5 border-b border-gray-100">
          {orgProfile?.has_logo ? (
            <img
              src={orgProfile.logo_data}
              alt="org logo"
              className="h-6 w-auto max-w-[28px] object-contain"
            />
          ) : (
            <Shield className="w-6 h-6 text-blue-600" />
          )}
          <span className="font-semibold text-gray-900">NetAudit</span>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-0.5">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                  isActive
                    ? "bg-blue-50 text-blue-700 font-medium"
                    : "text-gray-600 hover:bg-gray-100"
                }`
              }
            >
              <Icon className="w-4 h-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="px-3 py-4 border-t border-gray-100">
          <div className="px-3 py-2 text-xs text-gray-400 truncate">{user?.email}</div>
          <button
            onClick={logout}
            className="flex items-center gap-2.5 px-3 py-2.5 w-full rounded-lg text-sm text-gray-600 hover:bg-gray-100 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>

      {/* Floating scan progress panel */}
      <ScanProgressPanel />
    </div>
  );
}
