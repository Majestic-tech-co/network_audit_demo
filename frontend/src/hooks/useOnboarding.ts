import { useQuery } from "@tanstack/react-query";
import { api } from "../utils/api";

export interface OnboardingStatus {
  ai_configured: boolean;
  first_scan_done: boolean;
  agent_connected: boolean;
  users_invited: boolean;
  all_done: boolean;
}

export function useOnboarding() {
  // Pull real data from the dashboard stats + settings
  const { data: stats } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: () => api.get("/api/dashboard/stats").then(r => r.data),
  });

  const { data: settings } = useQuery({
    queryKey: ["org-settings"],
    queryFn: () => api.get("/api/settings").then(r => r.data),
  });

  const { data: users } = useQuery({
    queryKey: ["users"],
    queryFn: () => api.get("/api/users").then(r => r.data),
  });

  const ai_configured = Boolean(
    settings?.ai_provider === "ollama" || settings?.has_api_key
  );
  const first_scan_done = (stats?.total_devices ?? 0) > 0;
  const agent_connected = (stats?.agent_registered_devices ?? 0) > 0;
  const users_invited = (users?.length ?? 0) > 1;

  const all_done = ai_configured && first_scan_done && agent_connected && users_invited;

  return {
    status: {
      ai_configured,
      first_scan_done,
      agent_connected,
      users_invited,
      all_done,
    } as OnboardingStatus,
    isLoading: !stats || !settings,
  };
}
