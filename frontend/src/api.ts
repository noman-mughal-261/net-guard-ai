const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export type Alert = {
  _id: string;
  source_ip: string | null;
  label: string;
  confidence: number;
  created_at: string;
  analyst_status?: string;
};

export type BlockedIp = {
  ip: string;
  blocked_at: string;
  firewall_applied?: boolean;
  firewall_message?: string;
};

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(t || r.statusText);
  }
  return r.json() as Promise<T>;
}

export function getHealth() {
  return fetchJson<{ status: string }>("/api/health");
}

export function getAlerts() {
  return fetchJson<{ items: Alert[] }>("/api/alerts");
}

export function getLogs(limit = 500) {
  return fetchJson<{ items: Record<string, unknown>[] }>(`/api/logs?limit=${limit}`);
}

export function getBlockedIps() {
  return fetchJson<{ items: BlockedIp[] }>("/api/blocked-ips");
}

export function getAnalytics() {
  return fetchJson<{ threat_breakdown: { _id: string; count: number }[] }>(
    "/api/analytics/summary"
  );
}

export function getModelPerformance() {
  return fetchJson<Record<string, unknown>>("/api/model-performance");
}

export function blockIp(ip: string, analyst?: string) {
  const key = import.meta.env.VITE_BLOCK_API_KEY ?? "";
  return fetchJson<{
    ok: boolean;
    ip: string;
    firewall_applied?: boolean;
    firewall_message?: string;
    already_blocked?: boolean;
  }>("/api/block-ip", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}` },
    body: JSON.stringify({ ip, analyst: analyst ?? "dashboard" }),
  });
}

export function alertAction(alertId: string, action: "monitor" | "ignore") {
  return fetchJson<{ ok: boolean }>("/api/alert-action", {
    method: "POST",
    body: JSON.stringify({ alert_id: alertId, action }),
  });
}
