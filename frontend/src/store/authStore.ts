import { create } from "zustand";
import { persist } from "zustand/middleware";
import axios from "axios";

interface User {
  id: string;
  email: string;
  username: string;
  role: "it_admin" | "it_engineer" | "it_viewer" | "end_user";
  organization_id: string;
}

interface AuthState {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  login: (email: string, password: string, captchaToken?: string | null) => Promise<void>;
  logout: () => void;
  setUser: (user: User, accessToken: string, refreshToken?: string) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,

      login: async (email, password, captchaToken) => {
        const form = new FormData();
        form.append("username", email);
        form.append("password", password);
        const res = await axios.post("/api/auth/login", form, {
          headers: captchaToken ? { "X-Turnstile-Token": captchaToken } : {},
        });
        const { access_token, refresh_token, user } = res.data;
        set({
          user,
          accessToken: access_token,
          refreshToken: refresh_token,
          isAuthenticated: true,
        });
      },

      logout: () => {
        const refreshToken = get().refreshToken;
        set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false });
        // Revoke the session server-side; navigate regardless of whether the call succeeds.
        const done = () => { window.location.href = "/login"; };
        if (!refreshToken) return done();
        axios.post("/api/auth/logout", { refresh_token: refreshToken }).then(done, done);
      },

      setUser: (user, accessToken, refreshToken) =>
        set({ user, accessToken, refreshToken: refreshToken ?? null, isAuthenticated: true }),
    }),
    {
      name: "netaudit-auth",
      partialize: (s) => ({
        user: s.user,
        accessToken: s.accessToken,
        refreshToken: s.refreshToken,
        isAuthenticated: s.isAuthenticated,
      }),
    }
  )
);
