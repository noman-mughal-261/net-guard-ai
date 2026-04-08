import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getHistory, getScanStatus, login, signup, startScan, type HistoryItem } from "./api";

type User = { full_name: string; email: string };

const menu = ["Dashboard", "History", "Settings"];

function PageFrame({
  title,
  bg,
  children,
  onLogout,
  active,
  onNavigate,
}: {
  title: string;
  bg: string;
  children: ReactNode;
  onLogout: () => void;
  active: string;
  onNavigate: (key: string) => void;
}) {
  return (
    <div className="min-h-screen bg-cover bg-center p-4 md:p-6" style={{ backgroundImage: `url(${bg})` }}>
      <div className="mx-auto flex min-h-[92vh] max-w-7xl rounded-2xl border border-cyan-400/20 bg-[#0a0f1c]/80 shadow-[0_0_32px_rgba(0,195,255,0.2)] backdrop-blur-md">
        <aside className="w-20 border-r border-cyan-400/20 py-6">
          <div className="mb-8 text-center text-cyan-300 text-xl">AI</div>
          <div className="flex flex-col items-center gap-4">
            {menu.map((item) => (
              <button
                key={item}
                onClick={() => onNavigate(item)}
                className={`w-12 rounded-lg border p-2 text-xs transition ${
                  active === item ? "border-cyan-300 bg-cyan-400/20 text-cyan-200" : "border-cyan-400/20 text-slate-300 hover:bg-cyan-400/10"
                }`}
              >
                {item[0]}
              </button>
            ))}
          </div>
        </aside>
        <section className="flex-1 p-5 md:p-8">
          <header className="mb-6 flex items-center justify-between">
            <h1 className="text-3xl font-bold text-white">{title}</h1>
            <button onClick={onLogout} className="rounded-lg border border-cyan-300/40 px-3 py-2 text-cyan-100 hover:bg-cyan-400/10">Logout</button>
          </header>
          {children}
        </section>
      </div>
    </div>
  );
}

function Splash() {
  return (
    <div className="min-h-screen bg-cover bg-center" style={{ backgroundImage: "url('/assets/splash-bg.png')" }}>
      <div className="flex min-h-screen items-center justify-center bg-[#020613]/60">
        <div className="w-full max-w-md text-center">
          <h1 className="text-6xl font-extrabold text-white">NetGuard <span className="text-cyan-300">AI</span></h1>
          <p className="mt-4 text-2xl text-cyan-100">Loading...</p>
          <div className="mt-5 h-3 rounded-full bg-slate-900">
            <div className="loading-bar h-3 rounded-full bg-cyan-300" />
          </div>
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
    <div className="w-full max-w-md rounded-2xl border border-cyan-400/30 bg-[#0a0f1c]/70 p-7 shadow-[0_0_24px_rgba(0,195,255,0.25)]">
      <h2 className="mb-5 text-center text-3xl font-semibold text-white">{type === "login" ? "Login" : "Create Account"}</h2>
      {type === "signup" && <input className="ng-input" placeholder="Full Name" value={fullName} onChange={(e) => setFullName(e.target.value)} />}
      <input className="ng-input mt-3" placeholder="Email Address" value={email} onChange={(e) => setEmail(e.target.value)} />
      <input className="ng-input mt-3" type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
      {type === "signup" && <input className="ng-input mt-3" type="password" placeholder="Confirm Password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
      {type === "signup" && (
        <label className="mt-3 flex items-center gap-2 text-sm text-cyan-100">
          <input type="checkbox" checked={terms} onChange={(e) => setTerms(e.target.checked)} />
          I agree to Terms and Privacy Policy
        </label>
      )}
      {error && <p className="mt-3 text-sm text-rose-300">{error}</p>}
      <button onClick={submit} className="mt-4 w-full rounded-lg bg-cyan-500 py-3 font-semibold text-slate-900 hover:bg-cyan-300"> {type === "login" ? "LOGIN" : "SIGN UP"} </button>
    </div>
  );
}

function Dashboard({ onLogout, onNavigate }: { onLogout: () => void; onNavigate: (k: string) => void }) {
  const [scanId, setScanId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState<"Secure" | "Threat Detected">("Secure");
  const [issues, setIssues] = useState(0);
  const [threats, setThreats] = useState<{ name: string; type: string; time: string }[]>([]);
  const data = useMemo(() => Array.from({ length: 12 }).map((_, i) => ({ t: `${i}:00`, up: Math.max(2, Math.round((Math.sin(i / 2) + 1) * 8)), down: Math.max(2, Math.round((Math.cos(i / 2) + 1) * 8)) })), []);
  const runScan = async () => {
    const scan = await startScan();
    setScanId(scan.session_id);
    setProgress(0);
    const timer = setInterval(async () => {
      const state = await getScanStatus(scan.session_id);
      setProgress(state.progress);
      if (state.status === "complete") {
        setStatus(state.result.system_status);
        setIssues(state.result.issues_found);
        setThreats(state.result.threats);
        clearInterval(timer);
      }
    }, 1000);
  };
  return (
    <PageFrame title="Dashboard" bg="/assets/dashboard-bg.png" onLogout={onLogout} active="Dashboard" onNavigate={onNavigate}>
      <div className="mb-5 grid gap-4 md:grid-cols-4">
        <div className="glass-card md:col-span-2"><p className="text-cyan-100">System Status</p><p className={`text-2xl font-bold ${status === "Secure" ? "text-emerald-300" : "text-rose-300"}`}>{status}</p></div>
        <div className="glass-card"><p className="text-cyan-100">AI Analysis</p><p className="text-3xl font-bold text-cyan-200">{issues}</p></div>
        <div className="glass-card"><p className="text-cyan-100">Alerts</p><p className="text-3xl font-bold text-cyan-200">{threats.length}</p></div>
      </div>
      <div className="mb-5 rounded-xl border border-cyan-400/30 bg-[#0a0f1c]/70 p-4">
        <div className="mb-2 flex items-center justify-between"><h3 className="text-lg text-white">Network Scan</h3><button onClick={runScan} className="rounded-lg bg-cyan-500 px-4 py-2 font-semibold text-slate-900">Start Scan</button></div>
        <div className="h-2 rounded-full bg-slate-900"><div className="h-2 rounded-full bg-cyan-300 transition-all" style={{ width: `${progress}%` }} /></div>
        <p className="mt-2 text-sm text-cyan-100">{scanId ? `Scanning... ${progress}%` : "No active scan"}</p>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <div className="glass-card">
          <h3 className="mb-3 text-white">Network Traffic</h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data}><CartesianGrid stroke="#1e293b" /><XAxis dataKey="t" tick={{ fill: "#a5f3fc" }} /><YAxis tick={{ fill: "#a5f3fc" }} /><Tooltip /><Line type="monotone" dataKey="up" stroke="#00c3ff" /><Line type="monotone" dataKey="down" stroke="#38bdf8" /></LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="glass-card">
          <h3 className="mb-3 text-white">Threats Detected</h3>
          {threats.length === 0 ? <p className="text-cyan-100">No threats found.</p> : threats.map((t, i) => <div key={`${t.name}-${i}`} className="mb-2 flex justify-between border-b border-cyan-400/20 pb-2 text-cyan-100"><span>{t.name}</span><span>{t.type}</span></div>)}
        </div>
      </div>
    </PageFrame>
  );
}

function History({ onLogout, onNavigate }: { onLogout: () => void; onNavigate: (k: string) => void }) {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [selected, setSelected] = useState<HistoryItem | null>(null);
  useEffect(() => {
    getHistory().then((res) => setItems(res.items));
  }, []);
  return (
    <PageFrame title="History" bg="/assets/history-bg.png" onLogout={onLogout} active="History" onNavigate={onNavigate}>
      <div className="overflow-hidden rounded-xl border border-cyan-400/20 bg-[#0a0f1c]/70">
        <table className="w-full text-left text-cyan-100">
          <thead className="bg-[#0b1530]"><tr><th className="p-3">Device Name</th><th className="p-3">Date & Time</th><th className="p-3">Threats</th><th className="p-3">Details</th></tr></thead>
          <tbody>{items.map((row) => <tr key={row.id} className="border-t border-cyan-400/10"><td className="p-3">{row.device_name}</td><td className="p-3">{new Date(row.date_time).toLocaleString()}</td><td className="p-3">{row.threats_identified}</td><td className="p-3"><button className="rounded border border-cyan-300/30 px-3 py-1" onClick={() => setSelected(row)}>View</button></td></tr>)}</tbody>
        </table>
      </div>
      {selected && (
        <div className="mt-5 rounded-xl border border-cyan-400/30 bg-[#0a0f1c]/80 p-4 text-cyan-100">
          <h3 className="text-xl text-white">Record Details</h3>
          <p>IP: {selected.device_details.ip}</p>
          <p>Firewall: {selected.device_details.firewall_status}</p>
          <p className="mt-3 text-cyan-200">Threat List:</p>
          {selected.threats.map((t, i) => <p key={`${t.name}-${i}`}>- {t.name} ({t.type}) at {t.time}</p>)}
        </div>
      )}
    </PageFrame>
  );
}

export default function App() {
  const [user, setUser] = useState<User | null>(() => {
    const raw = localStorage.getItem("ng_user");
    return raw ? (JSON.parse(raw) as User) : null;
  });
  const [page, setPage] = useState<"splash" | "login" | "signup" | "dashboard" | "history">("splash");
  useEffect(() => {
    const t = setTimeout(() => setPage(user ? "dashboard" : "login"), 2200);
    return () => clearTimeout(t);
  }, [user]);
  const logout = () => {
    localStorage.removeItem("ng_user");
    setUser(null);
    setPage("login");
  };
  const nav = (key: string) => setPage(key === "History" ? "history" : "dashboard");
  if (page === "splash") return <Splash />;
  if (!user && page !== "signup") {
    return (
      <div className="auth-bg" style={{ backgroundImage: "url('/assets/login-bg.png')" }}>
        <div className="auth-overlay">
          <AuthCard type="login" onDone={(u) => { setUser(u); setPage("dashboard"); }} />
          <button className="mt-4 text-cyan-100 underline" onClick={() => setPage("signup")}>Need an account? Sign up</button>
        </div>
      </div>
    );
  }
  if (!user && page === "signup") {
    return (
      <div className="auth-bg" style={{ backgroundImage: "url('/assets/signup-bg.png')" }}>
        <div className="auth-overlay">
          <AuthCard type="signup" onDone={(u) => { setUser(u); setPage("dashboard"); }} />
          <button className="mt-4 text-cyan-100 underline" onClick={() => setPage("login")}>Already have an account? Login</button>
        </div>
      </div>
    );
  }
  return page === "history" ? <History onLogout={logout} onNavigate={nav} /> : <Dashboard onLogout={logout} onNavigate={nav} />;
}
