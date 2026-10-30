import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "react-hot-toast";
import { useAuthStore } from "./store/authStore";

// Pages
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import PrivacyPage from "./pages/PrivacyPage";
import ITDashboard from "./pages/ITDashboard";
import NetworkTopology from "./pages/NetworkTopology";
import FindingsPage from "./pages/FindingsPage";
import UserDashboard from "./pages/UserDashboard";
import SettingsPage from "./pages/SettingsPage";
import UsersPage from "./pages/UsersPage";
import SchedulesPage from "./pages/SchedulesPage";
import PacketCapturePage from "./pages/PacketCapturePage";
import Layout from "./components/shared/Layout";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 30_000, retry: 1 },
  },
});

function RequireAuth({ children, itOnly = false }: { children: React.ReactNode; itOnly?: boolean }) {
  const { user, isAuthenticated } = useAuthStore();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (itOnly && user?.role === "end_user") return <Navigate to="/my-device" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          {/* Public */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/privacy" element={<PrivacyPage />} />

          {/* IT Team Routes */}
          <Route path="/" element={<RequireAuth itOnly><Layout /></RequireAuth>}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<ITDashboard />} />
            <Route path="topology" element={<NetworkTopology />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="schedules" element={<SchedulesPage />} />
            <Route path="users" element={<UsersPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="capture" element={<PacketCapturePage />} />
          </Route>

          {/* End User Route */}
          <Route path="/my-device" element={<RequireAuth><UserDashboard /></RequireAuth>} />

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
      <Toaster position="top-right" />
    </QueryClientProvider>
  );
}
