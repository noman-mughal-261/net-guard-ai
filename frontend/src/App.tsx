import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  getDashboardSummary,
  getHistory,
  getScanStatus,
  login,
  signup,
  startScan,
  type DashboardSummary,
  type HistoryItem,
} from "./api";
import {
  IconActivity,
  IconAlertCircle,
  IconAlertTriangle,
  IconBell,
  IconChart,
  IconCheckCircle,
  IconChevronDown,
  IconFileText,
  IconLayoutDashboard,
  IconMenu,
  IconSettings,
  IconShield,
  IconWave,
  IconX,
} from "./Icons";

type User = { full_name: string; email: string };

type NavId = "dashboard" | "live" | "analytics" | "alerts" | "reports" | "settings";

const NAV: { id: NavId; label: string; icon: ReactNode }[] = [
  { id: "dashboard", label: "Dashboard", icon: <IconLayoutDashboard /> },
  { id: "live", label: "Live Monitoring", icon: <IconActivity /> },
  { id: "analytics", label: "Traffic Analytics", icon: <IconChart /> },
  { id: "alerts", label: "Alerts", icon: <IconBell /> },
  { id: "reports", label: "Reports", icon: <IconFileText /> },
  { id: "settings", label: "Settings", icon: <IconSettings /> },
];

const PAGE_TITLE: Record<NavId, string> = {
  dashboard: "Dashboard",
  live: "Live Monitoring",
  analytics: "Traffic Analytics",
  alerts: "Alerts",
  reports: "Reports",
  settings: "Settings",
};

/** Design tokens */
const C = {
  bg: "#0a0e14",
  card: "#161b22",
  border: "#30363d",
  blue: "#007bff",
  green: "#28a745",
  red: "#dc3545",
  orange: "#ffc107",
  muted: "#8b949e",
  text: "#ffffff",
};

/** Pie slice colors cycle for attack labels from the API */
const PIE_PALETTE = [C.red, C.green, C.blue, C.orange, "#6f42c1", "#fd7e14", "#20c997", "#e83e8c"];

function formatInt(n: number) {
  return n.toLocaleString("en-US");
}

function useMediaQuery(query: string) {
  const [matches, setMatches] = useState(() =>
    typeof window !== "undefined" ? window.matchMedia(query).matches : false
  );
  useEffect(() => {
    const mq = window.matchMedia(query);
    const sync = () => setMatches(mq.matches);
    sync();
    mq.addEventListener("change", sync);
    return () => mq.removeEventListener("change", sync);
  }, [query]);
  return matches;
}

function StatusBadge({ status }: { status: "Critical" | "Warning" | "Normal" }) {
  const styles =
    status === "Critical"
      ? "bg-[#dc3545]/20 text-[#dc3545] border-[#dc3545]/50"
      : status === "Warning"
        ? "bg-[#ffc107]/15 text-[#ffc107] border-[#ffc107]/40"
        : "bg-[#28a745]/20 text-[#28a745] border-[#28a745]/50";
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${styles}`}>
      {status}
    </span>
  );
}

function AppShell({
  user,
  activeNav,
  onNavigate,
  onLogout,
  children,
}: {
  user: User;
  activeNav: NavId;
  onNavigate: (id: NavId) => void;
  onLogout: () => void;
  children: ReactNode;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const isLg = useMediaQuery("(min-width: 1024px)");

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    };
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, []);

  useEffect(() => {
    if (isLg) setSidebarOpen(false);
  }, [isLg]);

  useEffect(() => {
    if (!isLg && sidebarOpen) {
      const prev = document.body.style.overflow;
      document.body.style.overflow = "hidden";
      return () => {
        document.body.style.overflow = prev;
      };
    }
  }, [isLg, sidebarOpen]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setSidebarOpen(false);
        setMenuOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const initial = user.full_name?.trim()?.[0]?.toUpperCase() ?? user.email[0]?.toUpperCase() ?? "?";

  const goNav = (id: NavId) => {
    onNavigate(id);
    setSidebarOpen(false);
  };

  return (
    <div className="flex h-[100dvh] w-full max-w-[100vw] overflow-hidden text-white" style={{ backgroundColor: C.bg }}>
      {!isLg && sidebarOpen && (
        <button
          type="button"
          aria-label="Close menu"
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-[1px] lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-[min(280px,88vw)] shrink-0 flex-col border-r py-4 pl-3 pr-2 transition-transform duration-200 ease-out sm:py-5 sm:pl-4 sm:pr-3 lg:static lg:z-auto lg:w-[240px] lg:translate-x-0 ${
          sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        }`}
        style={{ borderColor: C.border, backgroundColor: C.bg }}
        id="app-sidebar"
      >
        <div className="mb-6 flex items-center justify-between gap-2 px-2 sm:mb-8">
          <div className="flex min-w-0 items-center gap-2 sm:gap-2.5">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-white" style={{ backgroundColor: C.blue }}>
              <IconShield className="h-5 w-5" />
            </span>
            <span className="truncate text-sm font-bold tracking-tight sm:text-base">NETGUARD AI</span>
          </div>
          <button
            type="button"
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-[#8b949e] hover:bg-white/[0.06] lg:hidden"
            aria-label="Close navigation"
            onClick={() => setSidebarOpen(false)}
          >
            <IconX />
          </button>
        </div>
        <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto overscroll-contain pb-4 sm:gap-1">
          {NAV.map((item) => {
            const active = activeNav === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => goNav(item.id)}
                className={`relative flex w-full min-w-0 items-center gap-2 rounded-lg py-2.5 pl-3 pr-2 text-left text-sm transition sm:gap-3 ${
                  active
                    ? "font-medium text-white"
                    : "font-normal text-[#8b949e] hover:bg-white/[0.04] hover:text-white"
                }`}
                style={active ? { backgroundColor: "rgba(0, 123, 255, 0.18)" } : undefined}
              >
                {active && (
                  <span
                    className="absolute left-0 top-1/2 h-8 w-1 -translate-y-1/2 rounded-r"
                    style={{ backgroundColor: C.blue }}
                  />
                )}
                <span className={`shrink-0 ${active ? "text-white" : "text-[#8b949e]"}`}>{item.icon}</span>
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
        <header
          className="flex h-14 shrink-0 items-center gap-2 border-b px-3 sm:gap-3 sm:px-4 md:px-6"
          style={{ borderColor: C.border, backgroundColor: C.bg }}
        >
          <button
            type="button"
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-[#8b949e] transition hover:bg-white/[0.06] hover:text-white lg:hidden"
            aria-label="Open navigation menu"
            aria-expanded={sidebarOpen}
            aria-controls="app-sidebar"
            onClick={() => setSidebarOpen(true)}
          >
            <IconMenu />
          </button>
          <div className="flex min-w-0 flex-1 items-center justify-end gap-1 sm:gap-2">
            <button
              type="button"
              className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-[#8b949e] transition hover:bg-white/[0.06] hover:text-white"
              aria-label="Notifications"
            >
              <IconBell />
              <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-[#dc3545]" />
            </button>
            <div className="relative ml-0.5 sm:ml-2" ref={menuRef}>
              <button
                type="button"
                onClick={() => setMenuOpen((o) => !o)}
                aria-haspopup="menu"
                aria-expanded={menuOpen}
                className="flex max-w-[100vw] items-center gap-2 rounded-lg py-1.5 pl-1 pr-2 transition hover:bg-white/[0.06] sm:pr-2.5"
              >
                <span
                  className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-sm font-semibold text-white"
                  style={{ backgroundColor: "#30363d" }}
                >
                  {initial}
                </span>
                <span className="hidden max-w-[120px] truncate text-sm text-[#8b949e] min-[400px]:inline min-[400px]:max-w-[140px] sm:max-w-[180px]">
                  {user.full_name || user.email}
                </span>
                <IconChevronDown
                  className={`h-[18px] w-[18px] shrink-0 text-[#8b949e] transition-transform duration-200 ease-out ${menuOpen ? "rotate-180" : ""}`}
                />
              </button>
              {menuOpen && (
                <div
                  className="absolute right-0 top-full z-50 mt-1 min-w-[160px] max-w-[calc(100vw-1.5rem)] rounded-lg border py-1 shadow-xl"
                  style={{ backgroundColor: C.card, borderColor: C.border }}
                >
                  <button
                    type="button"
                    className="w-full px-4 py-2 text-left text-sm text-[#8b949e] hover:bg-white/[0.06] hover:text-white"
                    onClick={() => {
                      setMenuOpen(false);
                      onLogout();
                    }}
                  >
                    Log out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-x-hidden overflow-y-auto overscroll-y-contain px-3 py-4 sm:px-4 sm:py-5 md:px-6">
          <h1 className="mb-4 text-xl font-bold tracking-tight sm:mb-5 sm:text-2xl" style={{ color: C.text }}>
            {PAGE_TITLE[activeNav]}
          </h1>
          {children}
        </main>
      </div>
    </div>
  );
}

function MetricCard({
  label,
  value,
  icon,
  iconWrapClass,
}: {
  label: string;
  value: string;
  icon: ReactNode;
  iconWrapClass?: string;
}) {
  return (
    <div
      className="flex min-w-0 items-start justify-between gap-3 rounded-[10px] border p-3 shadow-lg sm:p-4"
      style={{
        backgroundColor: C.card,
        borderColor: C.border,
        boxShadow: "0 4px 24px rgba(0,0,0,0.35)",
      }}
    >
      <div className="min-w-0 flex-1">
        <p className="text-xs sm:text-sm" style={{ color: C.muted }}>
          {label}
        </p>
        <p className="mt-1 text-lg font-bold tabular-nums tracking-tight sm:mt-2 sm:text-2xl" style={{ color: C.text }}>
          {value}
        </p>
      </div>
      <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg sm:h-11 sm:w-11 ${iconWrapClass ?? ""}`}>{icon}</div>
    </div>
  );
}

function ChartCard({ title, subtitle, children, className = "" }: { title: string; subtitle?: string; children: ReactNode; className?: string }) {
  return (
    <div
      className={`flex min-w-0 flex-col rounded-[10px] border p-3 shadow-lg sm:p-4 ${className}`}
      style={{
        backgroundColor: C.card,
        borderColor: C.border,
        boxShadow: "0 4px 24px rgba(0,0,0,0.35)",
      }}
    >
      <div className="mb-1 shrink-0">
        <h2 className="text-sm font-semibold sm:text-base" style={{ color: C.text }}>
          {title}
        </h2>
        {subtitle && (
          <p className="mt-0.5 text-[11px] sm:text-xs" style={{ color: C.muted }}>
            {subtitle}
          </p>
        )}
      </div>
      <div className="min-h-0 min-w-0 flex-1">{children}</div>
    </div>
  );
}

function DashboardPage({
  user,
  activeNav,
  onNavigate,
  onLogout,
}: {
  user: User;
  activeNav: NavId;
  onNavigate: (id: NavId) => void;
  onLogout: () => void;
}) {
  const [scanId, setScanId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [dashLoading, setDashLoading] = useState(true);
  const [dashError, setDashError] = useState<string | null>(null);
  const isNarrowChart = useMediaQuery("(max-width: 639px)");

  const refreshSummary = useCallback(async () => {
    setDashLoading(true);
    setDashError(null);
    try {
      const data = await getDashboardSummary();
      setSummary(data);
    } catch (e) {
      setDashError(e instanceof Error ? e.message : "Failed to load dashboard data");
      setSummary(null);
    } finally {
      setDashLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshSummary();
  }, [refreshSummary]);

  const traffic24h = useMemo(() => {
    if (summary?.traffic_hourly?.length) return summary.traffic_hourly;
    return Array.from({ length: 24 }, (_, i) => ({
      hour: `${String(i).padStart(2, "0")}:00`,
      normal: 0,
      attack: 0,
    }));
  }, [summary]);

  const pieSlices = useMemo(() => {
    const dist = summary?.attack_distribution ?? [];
    return dist.map((d, i) => ({
      name: d.label,
      value: Math.max(0, d.count),
      color: PIE_PALETTE[i % PIE_PALETTE.length],
    }));
  }, [summary]);

  const metrics = summary?.metrics;

  const runScan = async () => {
    const scan = await startScan();
    setScanId(scan.session_id);
    setProgress(0);
    const timer = setInterval(async () => {
      const state = await getScanStatus(scan.session_id);
      setProgress(state.progress);
      if (state.status === "complete") {
        clearInterval(timer);
        await refreshSummary();
      }
    }, 1000);
  };

  const recentRows = summary?.recent_activity ?? [];
  const highlight = summary?.highlight;

  return (
    <AppShell user={user} activeNav={activeNav} onNavigate={onNavigate} onLogout={onLogout}>
      <div className="flex min-w-0 flex-col gap-4 sm:gap-5">
        {dashError && (
          <div
            className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-100"
            role="alert"
          >
            {dashError}
            <button type="button" className="ml-3 underline" onClick={() => refreshSummary()}>
              Retry
            </button>
          </div>
        )}

        <div className="grid grid-cols-1 gap-3 min-[480px]:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="Total traffic (flows)"
            value={dashLoading && !summary ? "—" : formatInt(metrics?.total_flows ?? 0)}
            icon={<IconWave className="text-[#8b949e]" />}
            iconWrapClass="bg-[#21262d]"
          />
          <MetricCard
            label="Active threats (open alerts)"
            value={dashLoading && !summary ? "—" : formatInt(metrics?.active_alerts ?? 0)}
            icon={<IconAlertTriangle className="text-[#dc3545]" />}
            iconWrapClass="bg-[#dc3545]/15"
          />
          <MetricCard
            label="Normal (flows)"
            value={dashLoading && !summary ? "—" : formatInt(metrics?.normal_flows ?? 0)}
            icon={<IconCheckCircle className="text-[#28a745]" />}
            iconWrapClass="bg-[#28a745]/15"
          />
          <MetricCard
            label="Attack (flows)"
            value={dashLoading && !summary ? "—" : formatInt(metrics?.attack_flows ?? 0)}
            icon={<IconAlertCircle className="text-[#dc3545]" />}
            iconWrapClass="bg-[#dc3545]/15"
          />
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <ChartCard title="Network Traffic Overview" subtitle="Last 24 Hours (flows analyzed)" className="min-h-0 lg:col-span-2 lg:min-h-[300px]">
            <div className="h-[clamp(200px,58vw,280px)] w-full min-w-0 pt-2 sm:h-[280px]">
              {dashLoading && !summary ? (
                <p className="flex h-full items-center justify-center text-sm" style={{ color: C.muted }}>
                  Loading chart…
                </p>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={traffic24h}
                    margin={{
                      top: 8,
                      right: isNarrowChart ? 4 : 12,
                      left: 0,
                      bottom: isNarrowChart ? 4 : 0,
                    }}
                  >
                    <CartesianGrid stroke="#30363d" strokeDasharray="3 3" />
                    <XAxis
                      dataKey="hour"
                      tick={{ fill: C.muted, fontSize: isNarrowChart ? 9 : 11 }}
                      tickLine={false}
                      axisLine={{ stroke: C.border }}
                      interval={isNarrowChart ? 3 : 2}
                    />
                    <YAxis
                      tick={{ fill: C.muted, fontSize: isNarrowChart ? 9 : 11 }}
                      tickLine={false}
                      axisLine={{ stroke: C.border }}
                      tickFormatter={(v) => formatInt(v)}
                      width={isNarrowChart ? 34 : 52}
                      allowDecimals={false}
                    />
                    <Tooltip
                      contentStyle={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: 8 }}
                      labelStyle={{ color: C.muted }}
                    />
                    <Legend
                      wrapperStyle={{ paddingTop: 8, fontSize: isNarrowChart ? 10 : 12 }}
                      iconType="line"
                      formatter={(value) => value as string}
                    />
                    <Line type="monotone" dataKey="normal" name="Normal Traffic" stroke={C.green} strokeWidth={2} dot={false} />
                    <Line type="monotone" dataKey="attack" name="Attack Traffic" stroke={C.red} strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </div>
          </ChartCard>
          <ChartCard title="Attack Distribution" subtitle="By label (non-normal flows)" className="min-h-0 lg:min-h-[300px]">
            <div className="flex h-[clamp(200px,65vw,280px)] w-full min-w-0 flex-col items-center justify-center pt-2 sm:h-[280px]">
              {pieSlices.length === 0 ? (
                <p className="px-2 text-center text-sm" style={{ color: C.muted }}>
                  No attack labels yet. Send flows to <code className="text-xs">POST /api/analyze</code>.
                </p>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieSlices}
                      cx="50%"
                      cy="50%"
                      innerRadius={isNarrowChart ? 38 : 56}
                      outerRadius={isNarrowChart ? 62 : 86}
                      paddingAngle={2}
                      dataKey="value"
                      nameKey="name"
                      label={
                        isNarrowChart
                          ? false
                          : ({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`
                      }
                    >
                      {pieSlices.map((entry) => (
                        <Cell key={entry.name} fill={entry.color} stroke={C.border} strokeWidth={1} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: 8 }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </ChartCard>
        </div>

        {highlight ? (
          <div
            className="rounded-[10px] border bg-gradient-to-r from-[#dc3545] via-[#c82333] to-[#bd2130] p-3 shadow-lg sm:p-4"
            style={{ borderColor: "rgba(255,255,255,0.15)" }}
          >
            <p className="flex flex-wrap items-center gap-2 text-base font-bold text-white sm:text-lg">
              <span aria-hidden>⚠️</span> <span>ALERT: {highlight.label}</span>
            </p>
            <p className="mt-2 break-words text-xs text-white/90 sm:text-sm">
              Source IP: {highlight.source_ip ?? "—"} · Confidence: {(highlight.confidence * 100).toFixed(0)}%
              {scanId != null && (
                <span className="block pt-1 text-white/70 sm:ml-3 sm:inline sm:pt-0">· Demo scan: {progress}%</span>
              )}
            </p>
            <button
              type="button"
              onClick={runScan}
              className="mt-3 w-full rounded-md bg-white/20 px-3 py-2 text-xs font-semibold text-white backdrop-blur hover:bg-white/30 sm:w-auto sm:py-1.5"
            >
              Run demo network scan
            </button>
          </div>
        ) : (
          <div
            className="rounded-[10px] border p-3 text-sm shadow-lg sm:p-4"
            style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted }}
          >
            <p className="text-white">No attack alert highlighted yet.</p>
            <p className="mt-1 text-xs sm:text-sm">
              Open alerts with non-normal labels appear here. Ingest traffic via{" "}
              <code className="text-[#8b949e]">POST /api/analyze</code>.
            </p>
            <button
              type="button"
              onClick={runScan}
              className="mt-3 w-full rounded-md border px-3 py-2 text-xs font-semibold sm:w-auto"
              style={{ borderColor: C.border, color: C.text }}
            >
              Run demo network scan
            </button>
            {scanId != null && <p className="mt-2 text-xs text-[#8b949e]">Demo scan: {progress}%</p>}
          </div>
        )}

        <div
          className="overflow-hidden rounded-[10px] border shadow-lg"
          style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: "0 4px 24px rgba(0,0,0,0.35)" }}
        >
          <div className="flex flex-wrap items-center justify-between gap-2 border-b px-3 py-2.5 sm:px-4 sm:py-3" style={{ borderColor: C.border }}>
            <h2 className="text-sm font-semibold sm:text-base">Recent Alerts</h2>
            <button
              type="button"
              className="text-xs font-medium sm:text-sm"
              style={{ color: C.blue }}
              onClick={() => refreshSummary()}
            >
              Refresh
            </button>
          </div>
          <div className="-mx-3 overflow-x-auto overscroll-x-contain px-3 sm:mx-0 sm:px-0">
            <table className="w-full min-w-[520px] text-left text-xs sm:min-w-[640px] sm:text-sm">
              <thead>
                <tr style={{ color: C.muted, borderBottom: `1px solid ${C.border}` }} className="border-b">
                  <th className="whitespace-nowrap px-2 py-2.5 font-medium sm:px-4 sm:py-3">Time</th>
                  <th className="whitespace-nowrap px-2 py-2.5 font-medium sm:px-4 sm:py-3">Source IP</th>
                  <th className="whitespace-nowrap px-2 py-2.5 font-medium sm:px-4 sm:py-3">Destination IP</th>
                  <th className="whitespace-nowrap px-2 py-2.5 font-medium sm:px-4 sm:py-3">Type</th>
                  <th className="whitespace-nowrap px-2 py-2.5 font-medium sm:px-4 sm:py-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {recentRows.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center" style={{ color: C.muted }}>
                      No alerts in the database yet.
                    </td>
                  </tr>
                ) : (
                  recentRows.map((row, i) => (
                    <tr key={`${row.time}-${row.source_ip}-${i}`} className="border-b" style={{ borderColor: C.border }}>
                      <td className="whitespace-nowrap px-2 py-2.5 tabular-nums sm:px-4 sm:py-3" style={{ color: C.text }}>
                        {row.time}
                      </td>
                      <td
                        className="max-w-[120px] truncate px-2 py-2.5 font-mono text-[11px] sm:max-w-none sm:px-4 sm:py-3 sm:text-xs"
                        style={{ color: C.muted }}
                        title={row.source_ip}
                      >
                        {row.source_ip}
                      </td>
                      <td
                        className="max-w-[120px] truncate px-2 py-2.5 font-mono text-[11px] sm:max-w-none sm:px-4 sm:py-3 sm:text-xs"
                        style={{ color: C.muted }}
                        title={row.dest_ip}
                      >
                        {row.dest_ip}
                      </td>
                      <td className="px-2 py-2.5 sm:px-4 sm:py-3" style={{ color: C.text }}>
                        {row.type}
                      </td>
                      <td className="px-2 py-2.5 sm:px-4 sm:py-3">
                        <StatusBadge status={row.status} />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </AppShell>
  );
}

function PlaceholderPage({
  user,
  activeNav,
  onNavigate,
  onLogout,
  message,
}: {
  user: User;
  activeNav: NavId;
  onNavigate: (id: NavId) => void;
  onLogout: () => void;
  message: string;
}) {
  return (
    <AppShell user={user} activeNav={activeNav} onNavigate={onNavigate} onLogout={onLogout}>
      <div
        className="rounded-[10px] border p-6 text-center text-sm shadow-lg sm:p-8 sm:text-base"
        style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted }}
      >
        <p className="break-words">{message}</p>
      </div>
    </AppShell>
  );
}

function LiveMonitoringPage(props: {
  user: User;
  activeNav: NavId;
  onNavigate: (id: NavId) => void;
  onLogout: () => void;
}) {
  const [scanId, setScanId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [log, setLog] = useState<string[]>([]);

  const runScan = async () => {
    setLog((l) => [...l, "Starting scan…"]);
    const scan = await startScan();
    setScanId(scan.session_id);
    setProgress(0);
    const timer = setInterval(async () => {
      const state = await getScanStatus(scan.session_id);
      setProgress(state.progress);
      if (state.status === "complete") {
        setLog((l) => [...l, `Complete. Issues: ${state.result.issues_found}`, ...state.result.threats.map((t) => `${t.name} (${t.type})`)]);
        clearInterval(timer);
      }
    }, 1000);
  };

  return (
    <AppShell user={props.user} activeNav={props.activeNav} onNavigate={props.onNavigate} onLogout={props.onLogout}>
      <div
        className="rounded-[10px] border p-4 shadow-lg sm:p-6"
        style={{ backgroundColor: C.card, borderColor: C.border }}
      >
        <p className="text-sm text-[#8b949e] sm:text-base">Run a demo network scan against the API session endpoint.</p>
        <button
          type="button"
          onClick={runScan}
          className="mt-4 w-full rounded-lg px-4 py-2.5 text-sm font-semibold text-white sm:w-auto"
          style={{ backgroundColor: C.blue }}
        >
          Start scan
        </button>
        {scanId && (
          <div className="mt-4">
            <div className="h-2 rounded-full bg-[#21262d]">
              <div className="h-2 rounded-full transition-all" style={{ width: `${progress}%`, backgroundColor: C.blue }} />
            </div>
            <p className="mt-2 text-xs text-[#8b949e]">{progress}%</p>
          </div>
        )}
        {log.length > 0 && (
          <pre className="mt-4 max-h-48 overflow-auto break-all rounded-lg bg-[#0a0e14] p-3 font-mono text-[11px] text-[#8b949e] sm:text-xs">{log.join("\n")}</pre>
        )}
      </div>
    </AppShell>
  );
}

function ReportsPage(props: {
  user: User;
  activeNav: NavId;
  onNavigate: (id: NavId) => void;
  onLogout: () => void;
}) {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [selected, setSelected] = useState<HistoryItem | null>(null);
  useEffect(() => {
    getHistory().then((res) => setItems(res.items));
  }, []);

  return (
    <AppShell user={props.user} activeNav={props.activeNav} onNavigate={props.onNavigate} onLogout={props.onLogout}>
      <div
        className="overflow-hidden rounded-[10px] border shadow-lg"
        style={{ backgroundColor: C.card, borderColor: C.border }}
      >
        <div className="-mx-3 overflow-x-auto overscroll-x-contain px-3 sm:mx-0 sm:px-0">
          <table className="w-full min-w-[480px] text-left text-xs sm:min-w-[560px] sm:text-sm">
            <thead>
              <tr className="border-b" style={{ borderColor: C.border, color: C.muted }}>
                <th className="whitespace-nowrap px-2 py-2.5 font-medium sm:px-4 sm:py-3">Device</th>
                <th className="whitespace-nowrap px-2 py-2.5 font-medium sm:px-4 sm:py-3">Date &amp; Time</th>
                <th className="whitespace-nowrap px-2 py-2.5 font-medium sm:px-4 sm:py-3">Threats</th>
                <th className="px-2 py-2.5 sm:px-4 sm:py-3" />
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={row.id} className="border-b" style={{ borderColor: C.border }}>
                  <td className="max-w-[100px] truncate px-2 py-2.5 sm:max-w-none sm:px-4 sm:py-3" title={row.device_name}>
                    {row.device_name}
                  </td>
                  <td className="whitespace-nowrap px-2 py-2.5 text-[#8b949e] sm:px-4 sm:py-3">{new Date(row.date_time).toLocaleString()}</td>
                  <td className="px-2 py-2.5 sm:px-4 sm:py-3">{row.threats_identified}</td>
                  <td className="px-2 py-2.5 sm:px-4 sm:py-3">
                    <button
                      type="button"
                      className="rounded border px-2 py-1 text-[11px] font-medium transition hover:bg-white/[0.06] sm:px-3 sm:text-xs"
                      style={{ borderColor: C.border, color: C.blue }}
                      onClick={() => setSelected(row)}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {selected && (
        <div
          className="mt-4 rounded-[10px] border p-3 shadow-lg sm:p-4"
          style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted }}
        >
          <h3 className="mb-2 text-sm font-semibold text-white sm:text-base">Record details</h3>
          <p>IP: {selected.device_details.ip}</p>
          <p>Firewall: {selected.device_details.firewall_status}</p>
          <ul className="mt-2 list-inside list-disc">
            {selected.threats.map((t, i) => (
              <li key={`${t.name}-${i}`}>
                {t.name} ({t.type}) — {t.time}
              </li>
            ))}
          </ul>
        </div>
      )}
    </AppShell>
  );
}

function Splash() {
  return (
    <div className="flex min-h-[100dvh] items-center justify-center px-4" style={{ backgroundColor: C.bg }}>
      <div className="w-full max-w-md text-center">
        <h1 className="text-3xl font-extrabold text-white sm:text-5xl">
          NetGuard <span style={{ color: C.blue }}>AI</span>
        </h1>
        <p className="mt-4 text-lg sm:text-xl" style={{ color: C.muted }}>
          Loading…
        </p>
        <div className="mt-6 h-2 overflow-hidden rounded-full bg-[#21262d]">
          <div className="loading-bar h-2 rounded-full" style={{ backgroundColor: C.blue }} />
        </div>
      </div>
    </div>
  );
}

function AuthCard({ type, onDone }: { type: "login" | "signup"; onDone: (u: User) => void }) {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [terms, setTerms] = useState(false);
  const [error, setError] = useState("");
  const submit = async () => {
    setError("");
    if (!/\S+@\S+\.\S+/.test(email)) return setError("Enter a valid email.");
    if (password.length < 6) return setError("Password must be at least 6 characters.");
    if (type === "signup") {
      if (!fullName.trim()) return setError("Full name is required.");
      if (password !== confirm) return setError("Passwords do not match.");
      if (!terms) return setError("Accept terms to continue.");
      await signup({ full_name: fullName, email, password });
    }
    const auth = await login({ email, password });
    localStorage.setItem("ng_user", JSON.stringify(auth.user));
    onDone(auth.user);
  };
  return (
    <div
      className="w-full max-w-md rounded-[10px] border p-5 shadow-xl sm:p-7"
      style={{ backgroundColor: C.card, borderColor: C.border }}
    >
      <h2 className="mb-4 text-center text-xl font-bold text-white sm:mb-5 sm:text-2xl">{type === "login" ? "Login" : "Create account"}</h2>
      {type === "signup" && <input className="ng-input" placeholder="Full name" value={fullName} onChange={(e) => setFullName(e.target.value)} />}
      <input className="ng-input mt-3" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
      <input className="ng-input mt-3" type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
      {type === "signup" && <input className="ng-input mt-3" type="password" placeholder="Confirm password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
      {type === "signup" && (
        <label className="mt-3 flex items-center gap-2 text-sm" style={{ color: C.muted }}>
          <input type="checkbox" checked={terms} onChange={(e) => setTerms(e.target.checked)} className="rounded border-gray-600" />
          I agree to the Terms and Privacy Policy
        </label>
      )}
      {error && <p className="mt-3 text-sm text-[#dc3545]">{error}</p>}
      <button
        onClick={submit}
        className="mt-4 w-full rounded-lg py-3 text-base font-semibold text-white transition hover:opacity-90"
        style={{ backgroundColor: C.blue }}
      >
        {type === "login" ? "Log in" : "Sign up"}
      </button>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState<User | null>(() => {
    const raw = localStorage.getItem("ng_user");
    const tok = localStorage.getItem("ng_token");
    if (!raw || !tok) return null;
    try {
      return JSON.parse(raw) as User;
    } catch {
      return null;
    }
  });
  const [page, setPage] = useState<"splash" | "login" | "signup" | "app">("splash");
  const [activeNav, setActiveNav] = useState<NavId>("dashboard");

  useEffect(() => {
    const t = setTimeout(() => setPage(user ? "app" : "login"), 2200);
    return () => clearTimeout(t);
  }, [user]);

  const logout = () => {
    localStorage.removeItem("ng_user");
    localStorage.removeItem("ng_token");
    setUser(null);
    setPage("login");
    setActiveNav("dashboard");
  };

  if (page === "splash") return <Splash />;
  if (!user && page !== "signup") {
    return (
      <div className="auth-bg flex min-h-[100dvh] items-center justify-center px-4 py-8" style={{ backgroundColor: C.bg }}>
        <div className="flex w-full max-w-md flex-col items-stretch sm:items-center">
          <AuthCard type="login" onDone={(u) => { setUser(u); setPage("app"); }} />
          <button type="button" className="mt-4 text-sm underline" style={{ color: C.blue }} onClick={() => setPage("signup")}>
            Need an account? Sign up
          </button>
        </div>
      </div>
    );
  }
  if (!user && page === "signup") {
    return (
      <div className="auth-bg flex min-h-[100dvh] items-center justify-center px-4 py-8" style={{ backgroundColor: C.bg }}>
        <div className="flex w-full max-w-md flex-col items-stretch sm:items-center">
          <AuthCard type="signup" onDone={(u) => { setUser(u); setPage("app"); }} />
          <button type="button" className="mt-4 text-sm underline" style={{ color: C.blue }} onClick={() => setPage("login")}>
            Already have an account? Log in
          </button>
        </div>
      </div>
    );
  }

  if (!user) return null;

  const shellProps = { user, onNavigate: setActiveNav, onLogout: logout, activeNav };

  switch (activeNav) {
    case "dashboard":
      return <DashboardPage {...shellProps} />;
    case "live":
      return <LiveMonitoringPage {...shellProps} />;
    case "analytics":
      return <PlaceholderPage {...shellProps} message="Traffic analytics view — connect your analytics API here." />;
    case "alerts":
      return <PlaceholderPage {...shellProps} message="Dedicated alerts inbox — wire to GET /api/alerts when ready." />;
    case "reports":
      return <ReportsPage {...shellProps} />;
    case "settings":
      return <PlaceholderPage {...shellProps} message="Account and system settings." />;
    default:
      return <DashboardPage {...shellProps} />;
  }
}
