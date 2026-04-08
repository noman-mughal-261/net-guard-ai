const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export type ThreatRecord = { name: string; type: string; time: string };
export type HistoryItem = {
  id: string;
  device_name: string;
  date_time: string;
  threats_identified: number;
  device_details: { ip: string; firewall_status: string };
  threats: ThreatRecord[];
};

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<T>;
}

export const signup = (payload: { full_name: string; email: string; password: string }) =>
  fetchJson<{ ok: boolean; message: string }>("/api/signup", {
    method: "POST",
    body: JSON.stringify(payload),
  });

export const login = (payload: { email: string; password: string }) =>
  fetchJson<{ ok: boolean; token: string; user: { full_name: string; email: string } }>("/api/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });

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
