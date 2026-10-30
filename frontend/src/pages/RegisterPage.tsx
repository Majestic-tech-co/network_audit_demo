// ─── RegisterPage.tsx ──────────────────────────────────────────────
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../utils/api";
import { useAuthStore } from "../store/authStore";
import { Shield } from "lucide-react";
import toast from "react-hot-toast";
import Turnstile, { TURNSTILE_SITE_KEY } from "../components/shared/Turnstile";

export function RegisterPage() {
  const [form, setForm] = useState({ email: "", username: "", password: "", organization_name: "" });
  const [loading, setLoading] = useState(false);
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [captchaReset, setCaptchaReset] = useState(0);
  const { setUser } = useAuthStore();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await api.post("/api/auth/register", form, {
        headers: captchaToken ? { "X-Turnstile-Token": captchaToken } : {},
      });
      setUser(res.data.user, res.data.access_token, res.data.refresh_token);
      navigate(res.data.user.role === "end_user" ? "/my-device" : "/dashboard");
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Registration failed");
      setCaptchaReset((n) => n + 1);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center justify-center gap-2 mb-8">
          <Shield className="w-8 h-8 text-blue-600" />
          <span className="text-2xl font-semibold text-gray-900">NetAudit</span>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-sm">
          <h1 className="text-lg font-semibold text-gray-900 mb-5">Create an account</h1>
          <form onSubmit={handleSubmit} className="space-y-4">
            {["email", "username", "password", "organization_name"].map(field => (
              <div key={field}>
                <label className="block text-sm font-medium text-gray-700 mb-1.5 capitalize">
                  {field.replace("_", " ")}{field === "organization_name" ? " (optional)" : ""}
                </label>
                <input
                  type={field === "password" ? "password" : field === "email" ? "email" : "text"}
                  value={(form as any)[field]}
                  onChange={e => setForm(f => ({ ...f, [field]: e.target.value }))}
                  required={field !== "organization_name"}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
            ))}
            <Turnstile onToken={setCaptchaToken} resetSignal={captchaReset} />
            <button
              type="submit"
              disabled={loading || (!!TURNSTILE_SITE_KEY && !captchaToken)}
              className="w-full py-2.5 bg-blue-600 text-white rounded-lg font-medium text-sm hover:bg-blue-700 transition-colors disabled:opacity-50"
            >
              {loading ? "Creating account…" : "Create account"}
            </button>
          </form>
          <p className="text-sm text-gray-500 text-center mt-4">
            Already have an account?{" "}
            <Link to="/login" className="text-blue-600 hover:text-blue-700 font-medium">Sign in</Link>
          </p>
          <p className="text-xs text-gray-400 text-center mt-2">
            <Link to="/privacy" className="hover:text-gray-600 underline">Privacy notice</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default RegisterPage;
