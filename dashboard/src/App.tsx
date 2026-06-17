import { useEffect, useState } from "react";
import { Link, NavLink, Route, Routes } from "react-router-dom";
import { DashboardPage } from "@/pages/Dashboard";
import { DigestPage } from "@/pages/Digest";
import { AuditPage } from "@/pages/Audit";
import { SessionsPage } from "@/pages/Sessions";
import { NotificationSettingsPage } from "@/pages/NotificationSettings";
import { SettingsPage } from "@/pages/Settings";
import { BillingPage } from "@/pages/Billing";
import { InventoryPage } from "@/pages/Inventory";
import { ListenerRewritesPage } from "@/pages/ListenerRewrites";
import { getHealth, getSessions, shutdownServer } from "@/lib/api";

// ---------------------------------------------------------------------------
// Navigation items
// ---------------------------------------------------------------------------

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
}

const NAV_ITEMS: NavItem[] = [
  {
    to: "/",
    label: "Dashboard",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 0 1 6 3.75h2.25A2.25 2.25 0 0 1 10.5 6v2.25a2.25 2.25 0 0 1-2.25 2.25H6a2.25 2.25 0 0 1-2.25-2.25V6ZM3.75 15.75A2.25 2.25 0 0 1 6 13.5h2.25a2.25 2.25 0 0 1 2.25 2.25V18a2.25 2.25 0 0 1-2.25 2.25H6A2.25 2.25 0 0 1 3.75 18v-2.25ZM13.5 6a2.25 2.25 0 0 1 2.25-2.25H18A2.25 2.25 0 0 1 20.25 6v2.25A2.25 2.25 0 0 1 18 10.5h-2.25a2.25 2.25 0 0 1-2.25-2.25V6ZM13.5 15.75a2.25 2.25 0 0 1 2.25-2.25H18a2.25 2.25 0 0 1 2.25 2.25V18A2.25 2.25 0 0 1 18 20.25h-2.25a2.25 2.25 0 0 1-2.25-2.25v-2.25Z" />
      </svg>
    ),
  },
  {
    to: "/digest",
    label: "Digest",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 0 0 2.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 0 0-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 0 0 .75-.75 2.25 2.25 0 0 0-.1-.664m-5.8 0A2.251 2.251 0 0 1 13.5 2.25H15a2.25 2.25 0 0 1 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25ZM6.75 12h.008v.008H6.75V12Zm0 3h.008v.008H6.75V15Zm0 3h.008v.008H6.75V18Z" />
      </svg>
    ),
  },
  {
    to: "/audit",
    label: "Live Audit",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z" />
      </svg>
    ),
  },
  {
    to: "/sessions",
    label: "Sessions",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M6 6.878V6a2.25 2.25 0 0 1 2.25-2.25h7.5A2.25 2.25 0 0 1 18 6v.878m-12 0c.235-.083.487-.128.75-.128h10.5c.263 0 .515.045.75.128m-12 0A2.25 2.25 0 0 0 4.5 9v.878m13.5-3A2.25 2.25 0 0 1 19.5 9v.878m0 0a2.246 2.246 0 0 0-.75-.128H5.25c-.263 0-.515.045-.75.128m15 0A2.25 2.25 0 0 1 21 12v6a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 18v-6c0-.98.626-1.813 1.5-2.122" />
      </svg>
    ),
  },
  {
    to: "/inventory",
    label: "Trusted Binaries",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 0 1-1.043 3.296 3.745 3.745 0 0 1-3.296 1.043A3.745 3.745 0 0 1 12 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 0 1-3.296-1.043 3.745 3.745 0 0 1-1.043-3.296A3.745 3.745 0 0 1 3 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 0 1 1.043-3.296 3.745 3.745 0 0 1 3.296-1.043A3.745 3.745 0 0 1 12 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 0 1 3.296 1.043 3.746 3.746 0 0 1 1.043 3.296A3.745 3.745 0 0 1 21 12Z" />
      </svg>
    ),
  },
  {
    to: "/listener-rewrites",
    label: "Listener Rewrites",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 21 3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" />
      </svg>
    ),
  },
  {
    to: "/notifications",
    label: "Notifications",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0" />
      </svg>
    ),
  },
  {
    to: "/billing",
    label: "Billing",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 8.25h19.5M2.25 9h19.5m-16.5 5.25h6m-6 2.25h3m-3.75 3h15a2.25 2.25 0 0 0 2.25-2.25V6.75A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25v10.5A2.25 2.25 0 0 0 4.5 19.5Z" />
      </svg>
    ),
  },
  {
    to: "/settings",
    label: "Settings",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 0 1 0-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28Z" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
      </svg>
    ),
  },
];

// ---------------------------------------------------------------------------
// App component
// ---------------------------------------------------------------------------

export function App() {
  const [stopping, setStopping] = useState(false);
  const [activeSessions, setActiveSessions] = useState(0);
  const [serverReachable, setServerReachable] = useState(true);
  // Daemon version, fetched from /api/health on first poll. Empty until
  // the first successful response — the sidebar chip stays blank
  // rather than showing a stale hardcoded number.
  const [daemonVersion, setDaemonVersion] = useState("");

  useEffect(() => {
    async function poll() {
      // Reachability is decided by the OPEN health endpoint only. The session
      // count comes from `/api/supervisor/sessions`, which is token-gated — a
      // 401 there means "this tab isn't authorised", NOT "the server is down".
      // Folding both into one Promise.all (as before) made a missing dashboard
      // token surface as a false "Server unreachable".
      try {
        const health = await getHealth();
        setServerReachable(true);
        setDaemonVersion(health.version);
      } catch {
        setServerReachable(false);
        setActiveSessions(0);
        return;
      }

      // Best-effort: ask the supervisor registry directly. Inferring "active"
      // from recent audit timestamps misses idle-but-live sessions (a
      // `grith exec claude` window where the user is reading the model's
      // output and not triggering proxy calls). An auth failure here just
      // leaves the active-session count at 0.
      try {
        const sessions = await getSessions();
        setActiveSessions(sessions.total);
      } catch {
        setActiveSessions(0);
      }
    }
    void poll();
    const interval = setInterval(() => void poll(), 5_000);
    return () => clearInterval(interval);
  }, []);

  const proxyActive = serverReachable && activeSessions > 0;

  const handleStopDashboard = async () => {
    if (stopping) return;
    setStopping(true);
    try {
      await shutdownServer();
    } catch {
      // Server may close before responding — that's expected.
    }
  };

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-white border-r border-grith-border flex flex-col">
        {/* Logo */}
        <div className="h-14 flex items-center px-4 border-b border-grith-border">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-[#06070a] flex items-center justify-center">
              <svg className="w-5 h-5" viewBox="0 0 24 26" fill="none">
                <path d="M12 1.5L22 7v11L12 23.5 2 18V7L12 1.5z" stroke="#00e5a0" strokeWidth="1.5"/>
                <circle cx="12" cy="12.5" r="2.5" fill="#00e5a0"/>
              </svg>
            </div>
            <span className="text-grith-text font-semibold text-sm tracking-tight">
              grith
            </span>
            <span className="text-[10px] text-grith-dim font-mono ml-auto">
              {daemonVersion ? `v${daemonVersion}` : ""}
            </span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive
                    ? "bg-green-light text-green-dark font-medium"
                    : "text-grith-muted hover:text-grith-text hover:bg-grith-surface"
                }`
              }
            >
              {item.icon}
              {item.label}
            </NavLink>
          ))}
        </nav>

        {/* Status footer */}
        <div className="px-4 py-3 border-t border-grith-border space-y-2">
          <div className="flex items-center gap-2">
            <div
              className={`w-2 h-2 rounded-full ${
                proxyActive
                  ? "bg-status-allow-green animate-pulse"
                  : serverReachable
                    ? "bg-status-queue-amber"
                    : "bg-status-deny-red"
              }`}
            />
            {proxyActive ? (
              <Link
                to="/sessions"
                className="text-xs text-grith-muted hover:text-grith-text transition-colors"
              >
                {`${activeSessions} active session${activeSessions !== 1 ? "s" : ""}`}
              </Link>
            ) : (
              <span className="text-xs text-grith-muted">
                {serverReachable ? "Idle — no active sessions" : "Server unreachable"}
              </span>
            )}
          </div>
          <button
            onClick={handleStopDashboard}
            disabled={stopping}
            className="w-full flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-lg text-xs text-grith-muted hover:text-status-deny-red hover:bg-grith-surface transition-colors disabled:opacity-50"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5.636 5.636a9 9 0 1 0 12.728 0M12 3v9" />
            </svg>
            {stopping ? "Stopping..." : "Stop Dashboard"}
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto bg-grith-surface">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/digest" element={<DigestPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/sessions" element={<SessionsPage />} />
          <Route path="/inventory" element={<InventoryPage />} />
          <Route
            path="/listener-rewrites"
            element={<ListenerRewritesPage />}
          />
          <Route path="/notifications" element={<NotificationSettingsPage />} />
          <Route path="/billing" element={<BillingPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </main>
    </div>
  );
}
