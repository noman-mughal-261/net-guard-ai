const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export type UserProfile = {
  full_name: string;
  email: string;
  avatar_url?: string | null;
};

export type ThreatRecord = { name: string; type: string; time: string };
export type HistoryItem = {
  id: string;
  device_name: string;
  date_time: string;
  threats_identified: number;
  device_details: { ip: string; firewall_status: string };
  threats: ThreatRecord[];
};

function authHeaders(): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  const t = typeof localStorage !== "undefined" ? localStorage.getItem("ng_token") : null;
  if (t) h["Authorization"] = `Bearer ${t}`;
  return h;
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { ...authHeaders(), ...(init?.headers as Record<string, string>) },
  });
  if (!response.ok) {
    const text = await response.text();
    let detail: string | undefined;
    try {
      const parsed = JSON.parse(text) as { detail?: string | { msg?: string }[] };
      if (typeof parsed.detail === "string") detail = parsed.detail;
      else if (Array.isArray(parsed.detail) && parsed.detail[0]?.msg) detail = parsed.detail[0].msg;
    } catch {
      /* plain-text error body (e.g. Internal Server Error) */
    }
    throw new Error(detail || text || response.statusText);
  }
  return response.json() as Promise<T>;
}

function bearerOnly(): Record<string, string> {
  const h: Record<string, string> = {};
  const t = typeof localStorage !== "undefined" ? localStorage.getItem("ng_token") : null;
  if (t) h["Authorization"] = `Bearer ${t}`;
  return h;
}

export function avatarSrc(url: string | null | undefined): string | undefined {
  if (!url) return undefined;
  if (url.startsWith("http://") || url.startsWith("https://")) return url;
  return `${API_BASE}${url}`;
}

export const signup = (payload: { full_name: string; email: string; password: string }) =>
  fetchJson<{ ok: boolean; message: string; token?: string }>("/api/signup", {
    method: "POST",
    body: JSON.stringify(payload),
  }).then((data) => {
    if (typeof localStorage !== "undefined" && data.token) localStorage.setItem("ng_token", data.token);
    return data;
  });

export const login = (payload: { email: string; password: string }) =>
  fetchJson<{ ok: boolean; token: string; user: UserProfile }>("/api/login", {
    method: "POST",
    body: JSON.stringify(payload),
  }).then((data) => {
    if (typeof localStorage !== "undefined" && data.token) localStorage.setItem("ng_token", data.token);
    return data;
  });

export const getMe = () => fetchJson<{ ok: boolean; user: UserProfile }>("/api/me");

export const updateProfile = (payload: { full_name: string }) =>
  fetchJson<{ ok: boolean; user: UserProfile }>("/api/profile", {
    method: "PATCH",
    body: JSON.stringify(payload),
  });

export const changePassword = (payload: { current_password: string; new_password: string }) =>
  fetchJson<{ ok: boolean; message: string }>("/api/profile/password", {
    method: "PATCH",
    body: JSON.stringify(payload),
  });

export const uploadAvatar = async (file: File) => {
  const form = new FormData();
  form.append("file", file);
  const response = await fetch(`${API_BASE}/api/profile/avatar`, {
    method: "POST",
    headers: bearerOnly(),
    body: form,
  });
  if (!response.ok) {
    const text = await response.text();
    let detail: string | undefined;
    try {
      const parsed = JSON.parse(text) as { detail?: string };
      if (typeof parsed.detail === "string") detail = parsed.detail;
    } catch {
      /* plain-text error body */
    }
    throw new Error(detail || text || response.statusText);
  }
  return response.json() as Promise<{ ok: boolean; avatar_url: string; user: UserProfile }>;
};

export const startScan = () => fetchJson<{ session_id: string }>("/api/scan", { method: "POST" });

export const getScanStatus = (sessionId: string) =>
  fetchJson<{
    session_id: string;
    status: "scanning" | "complete";
    progress: number;
    result: {
      device_name: string;
      device_ip: string;
      firewall_status: string;
      threats: ThreatRecord[];
      issues_found: number;
      system_status: "Secure" | "Threat Detected";
    };
  }>(`/api/scan/${sessionId}`);

export const getHistory = () => fetchJson<{ items: HistoryItem[] }>("/api/history");

export type DashboardMetrics = {
  total_flows: number;
  normal_flows: number;
  attack_flows: number;
  active_alerts: number;
};

export type DashboardHourly = { hour: string; normal: number; attack: number };

export type DashboardDistribution = { label: string; count: number };

export type DashboardRecentRow = {
  time: string;
  source_ip: string;
  dest_ip: string;
  type: string;
  status: "Critical" | "Warning" | "Normal";
};

export type DashboardHighlight = {
  label: string;
  confidence: number;
  source_ip: string | null;
} | null;

export type DashboardSummary = {
  metrics: DashboardMetrics;
  traffic_hourly: DashboardHourly[];
  attack_distribution: DashboardDistribution[];
  recent_activity: DashboardRecentRow[];
  highlight: DashboardHighlight;
};

export const getDashboardSummary = () => fetchJson<DashboardSummary>("/api/dashboard/summary");

export type AlertItem = {
  _id: string;
  created_at: string;
  source_ip: string | null;
  label: string;
  confidence: number;
  probabilities: Record<string, number>;
  log_id: string | null;
  analyst_status: string;
};

export const getAlerts = (limit: number = 50) => fetchJson<{ items: AlertItem[] }>(`/api/alerts?limit=${limit}`);

export type LogItem = {
  _id: string;
  created_at: string;
  source_ip: string | null;
  label: string;
  confidence: number;
  probabilities: Record<string, number>;
  features: Record<string, number>;
  alert_triggered: boolean;
};

export const getLogs = (limit: number = 50) => fetchJson<{ items: LogItem[] }>(`/api/logs?limit=${limit}`);
