import React, { useEffect, useMemo, useState } from "react";
import api from "../api/api";
import "./CapacityReport.css";

import StatCard from "./components/StatCard";
import ProgressBar from "./components/ProgressBar";
import SparklineBar from "./components/SparklineBar";
import TimeSeriesChart from "./components/TimeSeriesChart";
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

// ─── capacity-monitoring/overview helpers ──────────────────────
// The API expects datetime bounds like 2026-07-14T00:00:00 / 2026-07-15T23:59:59

// value for an <input type="datetime-local">, e.g. "2026-07-14T00:00"
function toLocalInput(d, endOfDay = false) {
  return `${toISODate(d)}T${endOfDay ? "23:59" : "00:00"}`;
}

// datetime-local gives "2026-07-14T00:00"; the API wants seconds too
function toApiDateTime(v, endOfDay = false) {
  if (!v) return "";
  if (v.length === 16) return `${v}:${endOfDay ? "59" : "00"}`;
  return v;
}

// "2026-07-15T11:23:22.432392+00:00" -> "11:23"
function hm(t) {
  const m = String(t || "").match(/T(\d{2}):(\d{2})/);
  return m ? `${m[1]}:${m[2]}` : "";
}

// down-sample a [{ t, value }] series to at most n points for the sparkline
function downsample(series, n = 16) {
  if (!Array.isArray(series) || series.length === 0) return [];
  if (series.length <= n) return series;
  const step = series.length / n;
  const out = [];
  for (let i = 0; i < n; i++) out.push(series[Math.floor(i * step)]);
  return out;
}

function seriesToTrend(series, n = 16) {
  return downsample(series, n).map((p) => ({ day: hm(p.t), value: Math.round(Number(p.value) || 0) }));
}

function avgOf(series) {
  if (!series || !series.length) return null;
  const sum = series.reduce((a, p) => a + (Number(p.value) || 0), 0);
  return Math.round(sum / series.length);
}
function peakOf(series) {
  if (!series || !series.length) return null;
  return Math.round(Math.max(...series.map((p) => Number(p.value) || 0)));
}

// Map the capacity-monitoring/overview response onto the shape the tabs consume,
// keeping the mock for sections the endpoint does not cover (network, alerts, per-agent bars).
function mapCapacityOverview(res, agentName, mock) {
  const cpuSeries = res.cpu_utilization_series || [];
  const memSeries = res.memory_utilization_series || [];
  const stoSeries = res.storage_utilization_series || [];
  const sum = res.summary || {};

  return {
    ...mock,
    summary: {
      ...mock.summary,
      avg_cpu: sum.avg_cpu_percent != null ? Math.round(sum.avg_cpu_percent) : avgOf(cpuSeries),
      peak_cpu: peakOf(cpuSeries),
      peak_cpu_agent: agentName,
      avg_memory: avgOf(memSeries),
      peak_memory: peakOf(memSeries),
      peak_memory_agent: agentName,
      avg_disk: avgOf(stoSeries),
      peak_disk: peakOf(stoSeries),
      peak_disk_agent: agentName,
      avg_bandwidth: sum.avg_bandwidth_mbps != null ? `${sum.avg_bandwidth_mbps} MB/s` : mock.summary.avg_bandwidth,
    },
    cpu: {
      ...mock.cpu,
      cpuTrend: seriesToTrend(cpuSeries),
      memoryTrend: seriesToTrend(memSeries),
    },
    storage: {
      ...mock.storage,
      diskTrend: seriesToTrend(stoSeries),
    },
    // full-resolution series for the interactive zoomable chart
    series: {
      cpu: cpuSeries,
      memory: memSeries,
      storage: stoSeries,
      agentCpu: res.agent_cpu_utilization_series || [],
      agentMemory: res.agent_memory_utilization_series || [],
    },
  };
}

// Fallback series (used before the API returns) built from the mock trend arrays,
// so the interactive chart always has something to render.
function seriesFromTrend(trend) {
  return (trend || []).map((p) => ({ t: p.day, value: p.value }));
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

// Series colours — one per entity, stable across every tab so a metric keeps its
// identity. Validated (CVD ΔE, chroma, contrast) against the white card surface;
// see the palette check in scripts/validate_palette.js.
const C = {
  cpu: "#2a78d6", // blue
  memory: "#008300", // green
  storage: "#eda100", // yellow — sub-3:1, relieved by the legend + tooltip
  agentCpu: "#eb6834", // orange — only ever paired with cpu
  agentMemory: "#4a3aa7", // violet — only ever paired with memory
};

// Initial (and "applied") filter values.
const DEFAULTS = {
  agentName: "TestAgent",
  fromDt: toLocalInput(new Date(Date.now() - 864e5), false),
  toDt: toLocalInput(new Date(), true),
};

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
  // ── search form: agent name + from/to datetime ───────────────
  const [agentName, setAgentName] = useState(DEFAULTS.agentName);
  const [fromDt, setFromDt] = useState(DEFAULTS.fromDt);
  const [toDt, setToDt] = useState(DEFAULTS.toDt);

  // the filters the displayed report actually belongs to — only updated on a
  // successful search, so the header does not track half-typed form edits
  const [applied, setApplied] = useState(DEFAULTS);

  const [agents, setAgents] = useState([]);

  const [activeTab, setActiveTab] = useState("overview");
  const [status, setStatus] = useState("idle"); // idle | loading | error | success
  const [data, setData] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [exporting, setExporting] = useState(null); // "pdf" | "docx" | null

  // ── range of the report on screen (from the applied filters) ─
  const range = useMemo(
    () => ({
      from: parseISO((applied.fromDt || "").slice(0, 10)),
      to: parseISO((applied.toDt || "").slice(0, 10)),
    }),
    [applied]
  );

  const periodText = useMemo(() => {
    const { from, to } = range;
    const yearPart = to.getFullYear();
    return `${prettyDate(from)} – ${prettyDate(to)}, ${yearPart}`;
  }, [range]);

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

  const buildParams = () => ({ from: toISODate(range.from), to: toISODate(range.to) });

  const handleSearch = async () => {
    const name = agentName.trim();
    if (!name) {
      setErrorMsg("Enter an agent name to search.");
      setStatus("error");
      return;
    }
    if (!fromDt || !toDt) {
      setErrorMsg("Pick both a From and a To date/time.");
      setStatus("error");
      return;
    }
    if (new Date(fromDt) > new Date(toDt)) {
      setErrorMsg("The From date/time must be before the To date/time.");
      setStatus("error");
      return;
    }

    setStatus("loading");
    setErrorMsg("");

    try {
      const res = await api.get("/api/v1/capacity-monitoring/overview", {
        params: {
          agent_name: name,
          from_dt: toApiDateTime(fromDt, false),
          to_dt: toApiDateTime(toDt, true),
        },
      });

      const agentList = await fetchAgents();
      const mock = buildCapacityMock();
      const merged = mapCapacityOverview(res.data || {}, name, mock);
      merged.agents = agentList || mock.agents;

      if (!agentList) setAgents(mock.agents);
      setData(merged);
      setApplied({ agentName: name, fromDt, toDt });
      setStatus("success");
    } catch (e) {
      setErrorMsg(
        e?.response?.data?.detail ||
          e?.message ||
          `Failed to load capacity data for "${name}".`
      );
      setStatus("error");
    }
  };

  // ── export ───────────────────────────────────────────────────
  const handleExportPdf = () => {
    if (!data) {
      handleSearch();
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
          <button className="cap-btn cap-btn-primary" onClick={handleSearch}>
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
      {/* ── header ── */}
      <header className="cap-topbar">
        <div className="cap-title">
          <span className="cap-title-icon">
            <ChartIcon />
          </span>
          <span className="cap-title-text">
            Capacity report
            <span className="cap-title-sub">
              {applied.agentName ? `${applied.agentName} · ` : ""}
              {periodText}
            </span>
          </span>
        </div>

        <div className="cap-header-actions">
          <span className="cap-pill cap-pill-agents">{counts.total} agents</span>
          {counts.degraded > 0 && <span className="cap-pill cap-pill-degraded">{counts.degraded} degraded</span>}
          {counts.offline > 0 && <span className="cap-pill cap-pill-offline">{counts.offline} offline</span>}

          <button type="button" className="cap-btn" onClick={handleExportPdf} disabled={exporting !== null}>
            {exporting === "pdf" ? "…" : "Export PDF"}
          </button>
        </div>
      </header>

      {/* ── search panel ── */}
      <form
        className="cap-controls"
        onSubmit={(e) => {
          e.preventDefault();
          handleSearch();
        }}
      >
        <label className="cap-field cap-field-grow">
          <span className="cap-field-label">Agent name</span>
          <input
            type="text"
            className="cap-input"
            placeholder="e.g. TestAgent"
            value={agentName}
            onChange={(e) => setAgentName(e.target.value)}
            list="cap-agent-options"
            autoComplete="off"
          />
          <datalist id="cap-agent-options">
            {agents.map((a) => (
              <option key={a.id} value={a.agent_name} />
            ))}
          </datalist>
        </label>

        <label className="cap-field">
          <span className="cap-field-label">From</span>
          <input
            type="datetime-local"
            className="cap-date"
            value={fromDt}
            max={toDt}
            onChange={(e) => setFromDt(e.target.value)}
          />
        </label>

        <label className="cap-field">
          <span className="cap-field-label">To</span>
          <input
            type="datetime-local"
            className="cap-date"
            value={toDt}
            min={fromDt}
            onChange={(e) => setToDt(e.target.value)}
          />
        </label>

        <button type="submit" className="cap-btn cap-btn-primary cap-btn-search" disabled={loading}>
          {loading && <span className="cap-spinner" aria-hidden="true" />}
          {loading ? "Searching…" : "Search"}
        </button>
      </form>

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
        <button className="cap-btn cap-btn-primary cap-btn-sm cap-regen" onClick={handleSearch} disabled={loading}>
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

// Resolve full-resolution series for the interactive chart, falling back to the
// mock trend arrays when the live API series are not present.
function resolveSeries(d) {
  const s = d.series || {};
  const cpu = d.cpu || {};
  const storage = d.storage || {};
  return {
    cpu: s.cpu && s.cpu.length ? s.cpu : seriesFromTrend(cpu.cpuTrend),
    memory: s.memory && s.memory.length ? s.memory : seriesFromTrend(cpu.memoryTrend),
    storage: s.storage && s.storage.length ? s.storage : seriesFromTrend(storage.diskTrend),
    agentCpu: s.agentCpu || [],
    agentMemory: s.agentMemory || [],
  };
}

// ════════════════════════════════════════════════════════════════
//  Tab bodies
// ════════════════════════════════════════════════════════════════
function OverviewTab({ d, agents, loading }) {
  const s = d.summary || {};
  const cpu = d.cpu || {};
  const ser = resolveSeries(d);
  return (
    <div className="cap-tab-body">
      <div className="cap-section-head">Summary</div>
      <StatRow>
        <StatCard loading={loading} label="Avg CPU" value={pct(s.avg_cpu)} sub="normal range" subColor="success" />
        <StatCard loading={loading} label="Avg memory" value={pct(s.avg_memory)} sub="watch threshold" subColor="warning" />
        <StatCard loading={loading} label="Avg bandwidth" value={s.avg_bandwidth} sub="within limits" subColor="success" />
        <StatCard loading={loading} label="Avg disk" value={pct(s.avg_disk)} sub="healthy" subColor="success" />
      </StatRow>
      <Section title="System utilization — CPU · memory · storage">
        {loading ? (
          <SkelLines n={6} />
        ) : (
          <TimeSeriesChart
            height={240}
            unit="%"
            series={[
              { key: "cpu", name: "CPU", color: C.cpu, area: true, data: ser.cpu },
              { key: "mem", name: "Memory", color: C.memory, data: ser.memory },
              { key: "sto", name: "Storage", color: C.storage, data: ser.storage },
            ]}
          />
        )}
      </Section>
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
  const ser = resolveSeries(d);
  return (
    <div className="cap-tab-body">
      <div className="cap-section-head">CPU and memory</div>
      <StatRow>
        <StatCard loading={loading} label="Avg CPU" value={pct(s.avg_cpu)} sub="normal" subColor="success" />
        <StatCard loading={loading} label="Peak CPU" value={pct(s.peak_cpu)} sub={s.peak_cpu_agent} subColor="danger" />
        <StatCard loading={loading} label="Avg memory" value={pct(s.avg_memory)} sub="watch" subColor="warning" />
        <StatCard loading={loading} label="Peak memory" value={pct(s.peak_memory)} sub={s.peak_memory_agent} subColor="danger" />
      </StatRow>
      <Section title="CPU usage — system vs agent">
        {loading ? (
          <SkelLines n={6} />
        ) : (
          <TimeSeriesChart
            height={220}
            unit="%"
            series={[
              { key: "cpu", name: "System CPU", color: C.cpu, area: true, data: ser.cpu },
              { key: "acpu", name: "Agent CPU", color: C.agentCpu, data: ser.agentCpu },
            ]}
          />
        )}
      </Section>
      <Section title="Memory usage — system vs agent">
        {loading ? (
          <SkelLines n={6} />
        ) : (
          <TimeSeriesChart
            height={220}
            unit="%"
            series={[
              { key: "mem", name: "System memory", color: C.memory, area: true, data: ser.memory },
              { key: "amem", name: "Agent memory", color: C.agentMemory, data: ser.agentMemory },
            ]}
          />
        )}
      </Section>
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
        <div className="cap-print-period">Period: {periodText}</div>
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
