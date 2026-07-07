import React, { useEffect, useMemo, useState } from "react";
import api from "../api/api";
import "./CapacityReport.css";

import StatCard from "./components/StatCard";
import ProgressBar from "./components/ProgressBar";
import SparklineBar from "./components/SparklineBar";
import EventList from "./components/EventList";
import AgentHealthList from "./components/AgentHealthList";
import AgentTable from "./components/AgentTable";
import AlertList from "./components/AlertList";
import { buildCapacityMock } from "./capacityMockData";

// ─── date helpers ──────────────────────────────────────────────
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function toISODate(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}
function prettyDate(d) {
  return `${MONTHS[d.getMonth()]} ${d.getDate()}`;
}
function parseISO(s) {
  const [y, m, d] = (s || "").split("-").map(Number);
  if (!y) return new Date();
  return new Date(y, (m || 1) - 1, d || 1);
}

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "cpumem", label: "CPU and memory" },
  { key: "network", label: "Network" },
  { key: "storage", label: "Storage" },
  { key: "health", label: "Agent health" },
  { key: "alerts", label: "Capacity alerts" },
];

// Capacity thresholds for the auto-coloured progress bars (red >75, amber >=61)
const BAR_THRESH = { dangerAt: 75, warnAt: 61 };

// ─── chart icon (no icon library) ──────────────────────────────
function ChartIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="3" y="12" width="4" height="8" rx="1" fill="#0F6E56" />
      <rect x="10" y="7" width="4" height="13" rx="1" fill="#0F6E56" opacity="0.8" />
      <rect x="17" y="3" width="4" height="17" rx="1" fill="#0F6E56" opacity="0.6" />
    </svg>
  );
}

export default function CapacityReport() {
  const [rangeType, setRangeType] = useState("7"); // "7" | "30" | "custom"
  const [customFrom, setCustomFrom] = useState(toISODate(new Date(Date.now() - 7 * 864e5)));
  const [customTo, setCustomTo] = useState(toISODate(new Date()));

  const [agents, setAgents] = useState([]);
  const [selectedAgent, setSelectedAgent] = useState("all");

  const [activeTab, setActiveTab] = useState("overview");
  const [status, setStatus] = useState("idle"); // idle | loading | error | success
  const [data, setData] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [exporting, setExporting] = useState(null); // "pdf" | "docx" | null

  // ── active date range ────────────────────────────────────────
  const range = useMemo(() => {
    let from;
    let to;
    if (rangeType === "custom") {
      from = parseISO(customFrom);
      to = parseISO(customTo);
    } else {
      to = new Date();
      from = new Date(Date.now() - Number(rangeType) * 864e5);
    }
    return { from, to };
  }, [rangeType, customFrom, customTo]);

  const periodText = useMemo(() => {
    const { from, to } = range;
    const yearPart = to.getFullYear();
    return `Period: ${prettyDate(from)} – ${prettyDate(to)}, ${yearPart}`;
  }, [range]);

  const agentIdsParam = selectedAgent === "all" ? undefined : String(selectedAgent);

  // status-pill counts
  const counts = useMemo(() => {
    const c = { total: agents.length, online: 0, degraded: 0, offline: 0 };
    agents.forEach((a) => {
      if (c[a.status] != null) c[a.status] += 1;
    });
    return c;
  }, [agents]);

  // ── preload dummy data on mount so the report renders at once ─
  useEffect(() => {
    const mock = buildCapacityMock();
    setAgents(mock.agents);
    setData(mock);
    setStatus("success");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── data fetching ────────────────────────────────────────────
  const fetchAgents = async () => {
    try {
      const res = await api.get("/api/v1/agents");
      const list = Array.isArray(res.data) ? res.data : res.data?.agents || [];
      if (list.length) {
        const normalized = list.map((a, i) => ({
          id: a.id ?? a.agent_id ?? i,
          agent_name: a.agent_name ?? a.name ?? `agent_${i}`,
          hostname: a.hostname ?? a.host ?? "unknown-host",
          os: a.os ?? a.platform ?? "—",
          cpu: a.cpu ?? null,
          memory: a.memory ?? null,
          disk: a.disk ?? null,
          status: a.status ?? "online",
          last_seen: a.last_seen ?? "unknown",
        }));
        setAgents(normalized);
        return normalized;
      }
    } catch (e) {
      /* fall through to mock */
    }
    return null;
  };

  const buildParams = () => {
    const p = { from: toISODate(range.from), to: toISODate(range.to) };
    if (agentIdsParam) p.agent_ids = agentIdsParam;
    return p;
  };

  const safeGet = async (url, params) => {
    try {
      const res = await api.get(url, { params });
      return res.data;
    } catch (e) {
      return null;
    }
  };

  const handleGenerate = async () => {
    setStatus("loading");
    setErrorMsg("");
    const params = buildParams();

    try {
      const [agentList, summary, cpu, network, storage, alerts] = await Promise.all([
        fetchAgents(),
        safeGet("/api/v1/reports/capacity/summary", params),
        safeGet("/api/v1/reports/capacity/cpu", params),
        safeGet("/api/v1/reports/capacity/network", params),
        safeGet("/api/v1/reports/capacity/storage", params),
        safeGet("/api/v1/reports/capacity/alerts", params),
      ]);

      const mock = buildCapacityMock();
      const merged = {
        agents: agentList || mock.agents,
        summary: summary || mock.summary,
        cpu: cpu || mock.cpu,
        network: network || mock.network,
        storage: storage || mock.storage,
        alerts: alerts?.alerts || alerts || mock.alerts,
      };

      if (!agentList) setAgents(mock.agents);
      setData(merged);
      setStatus("success");
    } catch (e) {
      setErrorMsg(e?.message || "Failed to generate the report.");
      setStatus("error");
    }
  };

  // ── export ───────────────────────────────────────────────────
  const handleExportPdf = () => {
    if (!data) {
      handleGenerate();
      return;
    }
    setExporting("pdf");
    window.requestAnimationFrame(() => {
      window.print();
      setExporting(null);
    });
  };

  const handleExportDocx = async () => {
    setExporting("docx");
    const params = buildParams();
    try {
      const res = await api.get("/api/v1/reports/capacity/export", {
        params: { ...params, format: "docx" },
        responseType: "blob",
      });
      const blob = new Blob([res.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `capacity-report-${params.from}_to_${params.to}.docx`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      alert("DOCX export: the backend endpoint is not available yet. Use Export PDF, which builds the full report in-browser.");
    } finally {
      setExporting(null);
    }
  };

  const loading = status === "loading";
  const d = data || {};

  const renderTab = () => {
    if (status === "idle") {
      return (
        <div className="cap-empty-state">
          <div className="cap-empty-icon">
            <ChartIcon />
          </div>
          <div className="cap-empty-title">No report generated yet</div>
          <div className="cap-empty-sub">
            Set your filters and click Generate to load the report.
          </div>
        </div>
      );
    }
    if (status === "error") {
      return (
        <div className="cap-error-banner">
          <span>{errorMsg || "Something went wrong loading the report."}</span>
          <button className="cap-btn cap-btn-primary" onClick={handleGenerate}>
            Retry
          </button>
        </div>
      );
    }

    switch (activeTab) {
      case "overview":
        return <OverviewTab d={d} agents={d.agents || []} loading={loading} />;
      case "cpumem":
        return <CpuMemTab d={d} loading={loading} />;
      case "network":
        return <NetworkTab d={d} loading={loading} />;
      case "storage":
        return <StorageTab d={d} loading={loading} />;
      case "health":
        return <HealthTab agents={d.agents || []} loading={loading} />;
      case "alerts":
        return <AlertsTab alerts={d.alerts || []} loading={loading} />;
      default:
        return null;
    }
  };

  return (
    <div className="cap-page">
      {/* ── top bar ── */}
      <div className="cap-topbar">
        <div className="cap-title">
          <ChartIcon />
          <span className="cap-title-text">
            Guardlynx <span className="cap-title-dim">— capacity report</span>
          </span>
        </div>

        <div className="cap-controls">
          <select className="cap-select" value={rangeType} onChange={(e) => setRangeType(e.target.value)}>
            <option value="7">Last 7 days</option>
            <option value="30">Last 30 days</option>
            <option value="custom">Custom</option>
          </select>

          {rangeType === "custom" && (
            <>
              <input type="date" className="cap-date" value={customFrom} max={customTo} onChange={(e) => setCustomFrom(e.target.value)} />
              <input type="date" className="cap-date" value={customTo} min={customFrom} onChange={(e) => setCustomTo(e.target.value)} />
            </>
          )}

          <select className="cap-select" value={selectedAgent} onChange={(e) => setSelectedAgent(e.target.value)}>
            <option value="all">All agents</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.agent_name}
              </option>
            ))}
          </select>

          <button className="cap-btn cap-btn-primary" onClick={handleGenerate} disabled={loading}>
            {loading ? "Generating…" : "Generate"}
          </button>

          <span className="cap-pill cap-pill-agents">{counts.total} agents</span>
          {counts.degraded > 0 && <span className="cap-pill cap-pill-degraded">{counts.degraded} degraded</span>}
          {counts.offline > 0 && <span className="cap-pill cap-pill-offline">{counts.offline} offline</span>}

          <button className="cap-btn" onClick={handleExportPdf} disabled={exporting !== null}>
            {exporting === "pdf" ? "…" : "Export PDF"}
          </button>
          {/* <button className="cap-btn" onClick={handleExportDocx} disabled={exporting !== null}>
            {exporting === "docx" ? "…" : "Export DOCX"}
          </button> */}
        </div>
      </div>

      {/* ── tab bar ── */}
      <div className="cap-tabbar">
        {TABS.map((t) => (
          <button
            key={t.key}
            className={`cap-tab ${activeTab === t.key ? "active" : ""}`}
            onClick={() => setActiveTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── tab content ── */}
      <div className="cap-content">{renderTab()}</div>

      {/* ── export bar (always visible) ── */}
      <div className="cap-exportbar">
        <span className="cap-export-label">Export report</span>
        <button className="cap-btn cap-btn-sm" onClick={handleExportPdf} disabled={exporting !== null}>
          {exporting === "pdf" ? "…" : "Export PDF"}
        </button>
        {/* <button className="cap-btn cap-btn-sm" onClick={handleExportDocx} disabled={exporting !== null}>
          {exporting === "docx" ? "…" : "Export DOCX"}
        </button> */}
        {/* <span className="cap-period">{periodText}</span>
        <button className="cap-btn cap-btn-primary cap-btn-sm cap-regen" onClick={handleGenerate} disabled={loading}>
          {loading ? "…" : "Regenerate"}
        </button> */}
      </div>

      {/* ── printable full report (all tabs) — only visible when printing ── */}
      {status === "success" && data && (
        <PrintableReport d={d} agents={d.agents || []} periodText={periodText} />
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
//  Shared bits
// ════════════════════════════════════════════════════════════════
function Section({ title, children, className = "" }) {
  return (
    <div className={`cap-card ${className}`}>
      {title && <div className="cap-card-title">{title}</div>}
      {children}
    </div>
  );
}
function StatRow({ children }) {
  return <div className="cap-statrow">{children}</div>;
}
function SkelLines({ n = 4 }) {
  return (
    <div className="cap-skel-lines">
      {Array.from({ length: n }).map((_, i) => (
        <div key={i} className="cap-skel" style={{ height: 14, margin: "8px 0" }} />
      ))}
    </div>
  );
}
function AgentBars({ items }) {
  return (
    <>
      {(items || []).map((a, i) => (
        <ProgressBar
          key={i}
          label={a.name}
          value={a.value}
          displayValue={a.displayValue}
          {...BAR_THRESH}
        />
      ))}
    </>
  );
}

// ════════════════════════════════════════════════════════════════
//  Tab bodies
// ════════════════════════════════════════════════════════════════
function OverviewTab({ d, agents, loading }) {
  const s = d.summary || {};
  const cpu = d.cpu || {};
  return (
    <div className="cap-tab-body">
      <div className="cap-section-head">Summary</div>
      <StatRow>
        <StatCard loading={loading} label="⊞ Avg CPU" value={pct(s.avg_cpu)} sub="normal range" subColor="success" />
        <StatCard loading={loading} label="◷ Avg memory" value={pct(s.avg_memory)} sub="watch threshold" subColor="warning" />
        <StatCard loading={loading} label="⇅ Avg bandwidth" value={s.avg_bandwidth} sub="within limits" subColor="success" />
        <StatCard loading={loading} label="▤ Avg disk" value={pct(s.avg_disk)} sub="healthy" subColor="success" />
      </StatRow>
      <div className="cap-two-col">
        <Section title="Resource utilization per agent">
          {loading ? <SkelLines n={6} /> : <AgentBars items={cpu.cpuPerAgent} />}
          {!loading && <OfflineRow agents={agents} />}
        </Section>
        <Section title="Agent health status">
          {loading ? <SkelLines n={6} /> : <AgentHealthList agents={agents} />}
        </Section>
      </div>
    </div>
  );
}

function CpuMemTab({ d, loading }) {
  const s = d.summary || {};
  const cpu = d.cpu || {};
  return (
    <div className="cap-tab-body">
      <div className="cap-section-head">CPU and memory</div>
      <StatRow>
        <StatCard loading={loading} label="Avg CPU" value={pct(s.avg_cpu)} sub="normal" subColor="success" />
        <StatCard loading={loading} label="Peak CPU" value={pct(s.peak_cpu)} sub={s.peak_cpu_agent} subColor="danger" />
        <StatCard loading={loading} label="Avg memory" value={pct(s.avg_memory)} sub="watch" subColor="warning" />
        <StatCard loading={loading} label="Peak memory" value={pct(s.peak_memory)} sub={s.peak_memory_agent} subColor="danger" />
      </StatRow>
      <div className="cap-three-col">
        <Section title="CPU — 7 day trend">
          {loading ? <SkelLines n={2} /> : <SparklineBar data={cpu.cpuTrend} height={54} />}
        </Section>
        <Section title="Memory — 7 day trend">
          {loading ? <SkelLines n={2} /> : <SparklineBar data={cpu.memoryTrend} height={54} dangerThreshold={80} warnThreshold={65} />}
        </Section>
        <Section title="CPU per agent (avg)">
          {loading ? <SkelLines n={5} /> : <AgentBars items={cpu.cpuPerAgent} />}
        </Section>
      </div>
      <div className="cap-two-col">
        <Section title="Top CPU events">
          {loading ? <SkelLines n={4} /> : <EventList events={cpu.events || []} maxItems={6} />}
        </Section>
        <Section title="Memory per agent (avg)">
          {loading ? <SkelLines n={5} /> : <AgentBars items={cpu.memoryPerAgent} />}
        </Section>
      </div>
    </div>
  );
}

function NetworkTab({ d, loading }) {
  const s = d.summary || {};
  const n = d.network || {};
  return (
    <div className="cap-tab-body">
      <div className="cap-section-head">Network utilization</div>
      <StatRow>
        <StatCard loading={loading} label="Avg bandwidth" value={s.avg_bandwidth} sub="normal" subColor="success" />
        <StatCard loading={loading} label="Peak bandwidth" value={s.peak_bandwidth} sub={s.peak_bandwidth_agent} subColor="danger" />
        <StatCard loading={loading} label="Total traffic" value={s.total_traffic} sub="7 day period" subColor="muted" />
        <StatCard loading={loading} label="Connections" value={s.total_connections} sub={`${s.blocked_connections} blocked`} subColor="warning" />
      </StatRow>
      <div className="cap-three-col">
        <Section title="Bandwidth — 7 day trend">
          {loading ? <SkelLines n={2} /> : <SparklineBar data={n.bandwidthTrend} height={54} dangerThreshold={90} warnThreshold={65} />}
        </Section>
        <Section title="Connections — 7 day trend">
          {loading ? <SkelLines n={2} /> : <SparklineBar data={n.connectionsTrend} height={54} dangerThreshold={90} warnThreshold={65} />}
        </Section>
        <Section title="Bandwidth per agent">
          {loading ? <SkelLines n={5} /> : <AgentBars items={n.bandwidthPerAgent} />}
        </Section>
      </div>
      <Section title="Protocol breakdown">
        {loading ? <SkelLines n={4} /> : (
          <div className="cap-proto-grid">
            {(n.protocols || []).map((p, i) => (
              <ProgressBar key={i} label={p.name} value={p.value} displayValue={`${p.value}%`} colorOverride={p.color} />
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

function StorageTab({ d, loading }) {
  const s = d.summary || {};
  const st = d.storage || {};
  return (
    <div className="cap-tab-body">
      <div className="cap-section-head">Storage and disk</div>
      <StatRow>
        <StatCard loading={loading} label="Avg disk usage" value={pct(s.avg_disk)} sub="healthy" subColor="success" />
        <StatCard loading={loading} label="Peak disk" value={pct(s.peak_disk)} sub={s.peak_disk_agent} subColor="danger" />
        <StatCard loading={loading} label="File events" value={s.file_events} sub="7 day period" subColor="muted" />
        <StatCard loading={loading} label="Data written" value={s.data_written} sub="total" subColor="muted" />
      </StatRow>
      <div className="cap-two-col">
        <Section title="Disk usage per agent">
          {loading ? <SkelLines n={6} /> : <AgentBars items={st.diskPerAgent} />}
        </Section>
        <Section title="Disk — 7 day trend">
          {loading ? <SkelLines n={4} /> : (
            <>
              <SparklineBar data={st.diskTrend} height={54} dangerThreshold={80} warnThreshold={60} />
              <div className="cap-subhead">File type breakdown</div>
              {(st.fileTypes || []).map((f, i) => (
                <ProgressBar key={i} label={f.name} value={f.value} displayValue={`${f.value}%`} colorOverride={f.color} />
              ))}
            </>
          )}
        </Section>
      </div>
    </div>
  );
}

function HealthTab({ agents, loading }) {
  const c = useMemo(() => {
    const o = { total: agents.length, online: 0, degraded: 0, offline: 0 };
    agents.forEach((a) => {
      if (o[a.status] != null) o[a.status] += 1;
    });
    return o;
  }, [agents]);

  return (
    <div className="cap-tab-body">
      <div className="cap-section-head">Agent health and inventory</div>
      <StatRow>
        <StatCard loading={loading} label="Total agents" value={c.total} sub="registered" subColor="muted" />
        <StatCard loading={loading} label="Online" value={c.online} sub="active now" subColor="success" />
        <StatCard loading={loading} label="Degraded" value={c.degraded} sub="needs watch" subColor="warning" />
        <StatCard loading={loading} label="Offline" value={c.offline} sub="needs attention" subColor="danger" />
      </StatRow>
      <AgentTable agents={agents} loading={loading} />
    </div>
  );
}

function AlertsTab({ alerts, loading }) {
  const c = useMemo(() => {
    const o = { total: alerts.length, critical: 0, warning: 0, resolved: 0 };
    alerts.forEach((a) => {
      if (o[a.priority] != null) o[a.priority] += 1;
    });
    return o;
  }, [alerts]);

  return (
    <div className="cap-tab-body">
      <div className="cap-section-head">Capacity alerts and thresholds</div>
      <StatRow>
        <StatCard loading={loading} label="Total alerts" value={c.total} sub="this week" subColor="muted" />
        <StatCard loading={loading} label="Critical" value={c.critical} sub="action needed" subColor="danger" />
        <StatCard loading={loading} label="Warnings" value={c.warning} sub="monitor" subColor="warning" />
        <StatCard loading={loading} label="Resolved" value={c.resolved} sub="this week" subColor="success" />
      </StatRow>
      {loading ? <SkelLines n={6} /> : <AlertList alerts={alerts} />}
    </div>
  );
}

// offline agents shown at the end of the per-agent bar lists (no metric)
function OfflineRow({ agents }) {
  const offline = (agents || []).filter((a) => a.status === "offline");
  if (offline.length === 0) return null;
  return (
    <>
      {offline.map((a) => (
        <div className="cap-offline-row" key={a.id}>
          <span className="cap-offline-name">{a.agent_name}</span>
          <span className="cap-offline-tag">offline</span>
        </div>
      ))}
    </>
  );
}

function pct(v) {
  return v == null ? "—" : `${v}%`;
}

// ════════════════════════════════════════════════════════════════
//  Printable report — every tab stacked, shown only in print / PDF
// ════════════════════════════════════════════════════════════════
function PrintableReport({ d, agents, periodText }) {
  return (
    <div className="cap-print-root" aria-hidden="true">
      <div className="cap-print-header">
        <div className="cap-print-brand">
          <ChartIcon />
          <span className="cap-print-title">Guardlynx — Capacity Report</span>
        </div>
        <div className="cap-print-period">{periodText}</div>
      </div>

      <PrintSection title="1. Overview">
        <OverviewTab d={d} agents={agents} loading={false} />
      </PrintSection>
      <PrintSection title="2. CPU and memory">
        <CpuMemTab d={d} loading={false} />
      </PrintSection>
      <PrintSection title="3. Network">
        <NetworkTab d={d} loading={false} />
      </PrintSection>
      <PrintSection title="4. Storage">
        <StorageTab d={d} loading={false} />
      </PrintSection>
      <PrintSection title="5. Agent health">
        <HealthTab agents={agents} loading={false} />
      </PrintSection>
      <PrintSection title="6. Capacity alerts">
        <AlertsTab alerts={d.alerts || []} loading={false} />
      </PrintSection>
    </div>
  );
}
function PrintSection({ title, children }) {
  return (
    <section className="cap-print-section">
      <h2 className="cap-print-h2">{title}</h2>
      {children}
    </section>
  );
}
