import axios, { AxiosError } from "axios";
import { useAuthStore } from "../store/authStore";

export const api = axios.create({ baseURL: "/" });

// Attach access token to every request
api.interceptors.request.use((config) => {
  try {
    const auth = JSON.parse(localStorage.getItem("netaudit-auth") || "{}");
    const token = auth?.state?.accessToken;
    if (token) config.headers.Authorization = `Bearer ${token}`;
  } catch {}
  return config;
});

// On 401: try refresh token, retry once, then logout
let isRefreshing = false;
let failedQueue: Array<{ resolve: Function; reject: Function }> = [];

function processQueue(error: AxiosError | null, token: string | null) {
  failedQueue.forEach((p) => (error ? p.reject(error) : p.resolve(token)));
  failedQueue = [];
}

api.interceptors.response.use(
  (r) => r,
  async (error: AxiosError) => {
    const original = error.config as any;

    if (error.response?.status !== 401 || original._retry) {
      return Promise.reject(error);
    }

    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        failedQueue.push({ resolve, reject });
      }).then((token) => {
        original.headers.Authorization = `Bearer ${token}`;
        return api(original);
      });
    }

    original._retry = true;
    isRefreshing = true;

    const storedRefreshToken = () => {
      try {
        return JSON.parse(localStorage.getItem("netaudit-auth") || "{}")?.state?.refreshToken as string | undefined;
      } catch {
        return undefined;
      }
    };

    try {
      const refreshToken = storedRefreshToken();

      if (!refreshToken) throw new Error("No refresh token");

      let res;
      try {
        res = await axios.post("/api/auth/refresh", { refresh_token: refreshToken });
      } catch (e) {
        // Refresh tokens are single use. If another tab rotated it first, localStorage already
        // holds its successor: use that once instead of treating this as a lost session.
        const latest = storedRefreshToken();
        if (!latest || latest === refreshToken) throw e;
        res = await axios.post("/api/auth/refresh", { refresh_token: latest });
      }
      const { access_token, refresh_token: new_refresh_token } = res.data;

      // Update Zustand store — persist middleware writes localStorage automatically
      useAuthStore.setState({ accessToken: access_token, refreshToken: new_refresh_token });

      processQueue(null, access_token);
      original.headers.Authorization = `Bearer ${access_token}`;
      return api(original);
    } catch (refreshError) {
      processQueue(refreshError as AxiosError, null);
      localStorage.removeItem("netaudit-auth");
      window.location.href = "/login";
      return Promise.reject(refreshError);
    } finally {
      isRefreshing = false;
    }
  }
);
