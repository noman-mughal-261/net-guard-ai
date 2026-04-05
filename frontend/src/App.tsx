import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  alertAction,
  blockIp,
  getAlerts,
  getAnalytics,
  getBlockedIps,
  getHealth,
  getLogs,
  getModelPerformance,
  type Alert,
  type BlockedIp,
} from "./api";

const COLORS = ["#22d3ee", "#a78bfa", "#f472b6", "#fbbf24", "#f87171", "#34d399"];

function usePoll<T>(fn: () => Promise<T>, ms: number) {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const ref = useRef(fn);
  ref.current = fn;
  const load = useCallback(() => {
    ref.current().then(setData).catch((e: Error) => setErr(e.message));
  }, []);
  useEffect(() => {
    load();
    const id = setInterval(load, ms);
    return () => clearInterval(id);
  }, [load, ms]);
  return { data, err, reload: load };
}

function BlockModal({
  ip,
  onClose,
  onConfirm,
}: {
  ip: string;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="w-full max-w-md rounded-xl border border-ng-border bg-ng-card p-6 shadow-xl">
        <h3 className="text-lg font-semibold text-white">Confirm IP block</h3>
        <p className="mt-2 text-sm text-ng-muted">
          Are you sure you want to block this IP? This applies an OS-level firewall rule on Linux
          hosts (iptables) and is only executed after analyst approval.
        </p>
        <p className="mt-4 rounded-lg bg-black/40 px-3 py-2 font-mono text-sm text-ng-accent">{ip}</p>
        <div className="mt-6 flex justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-ng-border px-4 py-2 text-sm text-ng-muted hover:bg-white/5"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className="rounded-lg bg-red-500/90 px-4 py-2 text-sm font-semibold text-white hover:bg-red-500"
          >
            Block IP
          </button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const health = usePoll(() => getHealth(), 15000);
  const alertsState = usePoll(() => getAlerts(), 5000);
  const blockedState = usePoll(() => getBlockedIps(), 8000);
  const analyticsState = usePoll(() => getAnalytics(), 12000);
  const logsState = usePoll(() => getLogs(800), 15000);
  const perfState = usePoll(() => getModelPerformance(), 60000);

  const [modalIp, setModalIp] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const blockedSet = useMemo(() => {
    const s = new Set<string>();
    (blockedState.data?.items ?? []).forEach((b: BlockedIp) => s.add(b.ip));
    return s;
  }, [blockedState.data]);

  const pieData = useMemo(() => {
    const rows = analyticsState.data?.threat_breakdown ?? [];
    return rows.map((r) => ({ name: r._id || "unknown", value: r.count }));
  }, [analyticsState.data]);

  const timeSeries = useMemo(() => {
    const items = [...(logsState.data?.items ?? [])].reverse();
    const buckets: Record<string, number> = {};
    for (const row of items) {
      const t = String(row.created_at ?? "").slice(0, 13);
      if (!t) continue;
      buckets[t] = (buckets[t] ?? 0) + 1;
    }
    return Object.entries(buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .slice(-24)
      .map(([hour, count]) => ({ hour, count }));
  }, [logsState.data]);

  const confirmBlock = async () => {
    if (!modalIp) return;
    try {
      const res = await blockIp(modalIp);
      setActionMsg(
        res.already_blocked
          ? `${modalIp} was already blocked.`
          : res.firewall_applied
            ? `${modalIp} blocked. Firewall: ${res.firewall_message ?? "ok"}`
            : `${modalIp} recorded. ${res.firewall_message ?? ""}`
      );
      blockedState.reload();
      alertsState.reload();
    } catch (e) {
      setActionMsg((e as Error).message);
    } finally {
      setModalIp(null);
    }
  };

  const onMonitor = async (a: Alert) => {
    try {
      await alertAction(a._id, "monitor");
      setActionMsg(`Alert ${a._id} marked monitoring`);
      alertsState.reload();
    } catch (e) {
      setActionMsg((e as Error).message);
    }
  };

  const onIgnore = async (a: Alert) => {
    try {
      await alertAction(a._id, "ignore");
      setActionMsg(`Alert ${a._id} ignored`);
      alertsState.reload();
    } catch (e) {
      setActionMsg((e as Error).message);
    }
  };

  const cm = perfState.data?.confusion_matrix as number[][] | undefined;
  const labels = perfState.data?.labels as string[] | undefined;

  return (
    <div className="min-h-screen">
      <header className="border-b border-ng-border bg-ng-card/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div>
            <h1 className="text-xl font-bold tracking-tight">NetGuard AI</h1>
            <p className="text-xs text-ng-muted">Human-in-the-loop Security Operations Center</p>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <span
              className={`inline-flex items-center gap-2 rounded-full px-3 py-1 ${
                health.err || health.data?.status !== "ok"
                  ? "bg-amber-500/20 text-amber-200"
                  : "bg-emerald-500/15 text-emerald-300"
              }`}
            >
              <span className="h-2 w-2 rounded-full bg-current" />
              {health.err
                ? "API unreachable"
                : health.data?.status === "ok"
                  ? "API + DB healthy"
                  : "API up (DB degraded)"}
            </span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-8 px-6 py-8">
        {actionMsg && (
          <div className="rounded-lg border border-ng-border bg-ng-card px-4 py-3 text-sm text-ng-muted">
            {actionMsg}
            <button
              type="button"
              className="ml-3 text-ng-accent underline"
              onClick={() => setActionMsg(null)}
            >
              dismiss
            </button>
          </div>
        )}

        <section>
          <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-ng-muted">
            Live alerts
          </h2>
          <div className="overflow-hidden rounded-xl border border-ng-border bg-ng-card">
            <table className="w-full text-left text-sm">
              <thead className="bg-black/30 text-xs uppercase text-ng-muted">
                <tr>
                  <th className="px-4 py-3">Source IP</th>
                  <th className="px-4 py-3">Threat</th>
                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ng-border">
                {(alertsState.data?.items ?? []).map((a) => {
                  const ip = a.source_ip ?? "—";
                  const isBlocked = ip !== "—" && blockedSet.has(ip);
                  return (
                    <tr key={a._id} className="hover:bg-white/[0.02]">
                      <td className="px-4 py-3 font-mono text-xs">{ip}</td>
                      <td className="px-4 py-3 font-medium text-white">{a.label}</td>
                      <td className="px-4 py-3">{(a.confidence * 100).toFixed(1)}%</td>
                      <td className="px-4 py-3 text-xs text-ng-muted">{a.created_at}</td>
                      <td className="px-4 py-3">
                        {isBlocked ? (
                          <span className="rounded-full bg-red-500/20 px-2 py-0.5 text-xs text-red-300">
                            Blocked
                          </span>
                        ) : (
                          <span className="rounded-full bg-white/10 px-2 py-0.5 text-xs text-ng-muted">
                            {a.analyst_status ?? "open"}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex flex-wrap justify-end gap-2">
                          <button
                            type="button"
                            disabled={!a.source_ip || isBlocked}
                            onClick={() => {
                              if (a.source_ip) setModalIp(a.source_ip);
                            }}
                            className="rounded-md bg-red-500/20 px-2 py-1 text-xs font-medium text-red-300 hover:bg-red-500/30 disabled:opacity-40"
                          >
                            Block IP
                          </button>
                          <button
                            type="button"
                            onClick={() => onMonitor(a)}
                            className="rounded-md bg-amber-500/15 px-2 py-1 text-xs font-medium text-amber-200 hover:bg-amber-500/25"
                          >
                            Monitor
                          </button>
                          <button
                            type="button"
                            onClick={() => onIgnore(a)}
                            className="rounded-md bg-white/10 px-2 py-1 text-xs text-ng-muted hover:bg-white/15"
                          >
                            Ignore
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {(alertsState.data?.items ?? []).length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-ng-muted">
                      No alerts yet. Send flows to <code className="text-ng-accent">/api/analyze</code>
                      .
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="grid gap-6 lg:grid-cols-2">
          <div className="rounded-xl border border-ng-border bg-ng-card p-4">
            <h3 className="mb-2 text-sm font-semibold text-ng-muted">Threat breakdown</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={90}
                    paddingAngle={2}
                  >
                    {pieData.map((_, i) => (
                      <Cell key={i} fill={COLORS[i % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="rounded-xl border border-ng-border bg-ng-card p-4">
            <h3 className="mb-2 text-sm font-semibold text-ng-muted">Traffic volume (logs)</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={timeSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                  <XAxis dataKey="hour" tick={{ fill: "#9ca3af", fontSize: 10 }} />
                  <YAxis tick={{ fill: "#9ca3af", fontSize: 10 }} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#22d3ee" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>

        <section className="rounded-xl border border-ng-border bg-ng-card p-4">
          <h3 className="mb-4 text-sm font-semibold text-ng-muted">Model performance (hold-out)</h3>
          {perfState.err && (
            <p className="text-sm text-amber-300">Metrics unavailable: {perfState.err}</p>
          )}
          {perfState.data && (
            <div className="grid gap-6 lg:grid-cols-3">
              <div>
                <p className="text-xs text-ng-muted">Accuracy</p>
                <p className="text-2xl font-semibold">
                  {Number(perfState.data.accuracy).toFixed(3)}
                </p>
              </div>
              <div>
                <p className="text-xs text-ng-muted">F1 (weighted)</p>
                <p className="text-2xl font-semibold">
                  {Number(perfState.data.f1_weighted).toFixed(3)}
                </p>
              </div>
              <div className="lg:col-span-1" />
              {cm && labels && (
                <div className="lg:col-span-3 overflow-x-auto">
                  <p className="mb-2 text-xs text-ng-muted">Confusion matrix</p>
                  <table className="border-collapse text-xs">
                    <thead>
                      <tr>
                        <th className="p-1" />
                        {labels.map((l) => (
                          <th key={l} className="p-1 text-ng-muted">
                            {l}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {cm.map((row, i) => (
                        <tr key={i}>
                          <td className="p-1 pr-2 font-medium text-ng-muted">{labels[i]}</td>
                          {row.map((c, j) => (
                            <td key={j} className="border border-ng-border p-1 text-center">
                              {c}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </section>

        <section>
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-ng-muted">
            Blocked IPs
          </h2>
          <ul className="rounded-xl border border-ng-border bg-ng-card divide-y divide-ng-border">
            {(blockedState.data?.items ?? []).length === 0 && (
              <li className="px-4 py-6 text-sm text-ng-muted">No blocked IPs</li>
            )}
            {(blockedState.data?.items ?? []).map((b) => (
              <li key={b.ip} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
                <span className="font-mono text-sm">{b.ip}</span>
                <span className="text-xs text-ng-muted">{b.blocked_at}</span>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs ${
                    b.firewall_applied ? "bg-emerald-500/20 text-emerald-300" : "bg-amber-500/15 text-amber-200"
                  }`}
                >
                  {b.firewall_applied ? "Firewall applied" : "Recorded only"}
                </span>
              </li>
            ))}
          </ul>
        </section>
      </main>

      {modalIp && (
        <BlockModal ip={modalIp} onClose={() => setModalIp(null)} onConfirm={confirmBlock} />
      )}
    </div>
  );
}
