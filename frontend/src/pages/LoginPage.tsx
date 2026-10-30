import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuthStore } from "../store/authStore";
import { Shield, Loader } from "lucide-react";
import toast from "react-hot-toast";
import axios from "axios";
import Turnstile, { TURNSTILE_SITE_KEY } from "../components/shared/Turnstile";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [ldapEnabled, setLdapEnabled] = useState(false);
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [captchaReset, setCaptchaReset] = useState(0);
  const { login } = useAuthStore();
  const navigate = useNavigate();

  // Public endpoint — no auth token needed, use plain axios not the intercepted api client
  useEffect(() => {
    axios.get("/api/auth/login-config")
      .then(r => setLdapEnabled(r.data.ldap_enabled ?? false))
      .catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await login(email, password, captchaToken);
      const role = useAuthStore.getState().user?.role;
      navigate(role === "end_user" ? "/my-device" : "/dashboard");
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Incorrect email or password");
      setCaptchaReset((n) => n + 1); // Turnstile tokens are single-use
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center justify-center gap-2.5 mb-8">
          <div className="w-9 h-9 bg-blue-600 rounded-xl flex items-center justify-center">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <span className="text-2xl font-semibold text-gray-900">NetAudit</span>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-sm">
          <h1 className="text-lg font-semibold text-gray-900 mb-1">Sign in</h1>
          <p className="text-sm text-gray-400 mb-5">
            {ldapEnabled
              ? "Use your corporate credentials or local account"
              : "Sign in to your account"}
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">
                Email {ldapEnabled && <span className="text-gray-400 font-normal">or username</span>}
              </label>
              <input
                type="text"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                autoFocus
                autoComplete="username"
                className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder={ldapEnabled ? "you@company.com or jsmith" : "you@company.com"}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">Password</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                autoComplete="current-password"
                className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="••••••••"
              />
            </div>
            <Turnstile onToken={setCaptchaToken} resetSignal={captchaReset} />
            <button
              type="submit"
              disabled={loading || (!!TURNSTILE_SITE_KEY && !captchaToken)}
              className="w-full py-2.5 bg-blue-600 text-white rounded-lg font-medium text-sm hover:bg-blue-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {loading && <Loader className="w-4 h-4 animate-spin" />}
              {loading ? "Signing in…" : "Sign in"}
            </button>
          </form>

          <p className="text-sm text-gray-500 text-center mt-4">
            Don't have an account?{" "}
            <Link to="/register" className="text-blue-600 hover:text-blue-700 font-medium">Register</Link>
          </p>
        </div>

        <p className="text-center text-xs text-gray-400 mt-4">
          <Link to="/privacy" className="hover:text-gray-600 underline">Privacy notice</Link>
        </p>

        {ldapEnabled && (
          <p className="text-center text-xs text-gray-400 mt-4">
            Active Directory login enabled — use your Windows credentials
          </p>
        )}
      </div>
    </div>
  );
}
