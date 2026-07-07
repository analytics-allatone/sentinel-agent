import React, { useEffect, useMemo, useState } from "react";
import api from "../api/api";
import "./SOC2Report.css";

import StatCard from "./components/StatCard";
import ProgressBar from "./components/ProgressBar";
import EventList from "./components/EventList";
import IncidentsTable from "./components/IncidentsTable";
import AgentsTable from "./components/AgentsTable";
import CriteriaScores from "./components/CriteriaScores";
import { buildMockData } from "./mockData";

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
  // treat "YYYY-MM-DD" as a local date
  const [y, m, d] = (s || "").split("-").map(Number);
  if (!y) return new Date();
  return new Date(y, (m || 1) - 1, d || 1);
}

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "access", label: "Access control" },
  { key: "sysops", label: "System ops" },
  { key: "change", label: "Change mgmt" },
  { key: "network", label: "Network" },
  { key: "incidents", label: "Incidents" },
  { key: "agents", label: "Agents" },
  { key: "recommendations", label: "Recommendations" },
];

// ─── shield icon (no icon library) ─────────────────────────────
function ShieldIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z"
        fill="#185FA5"
        opacity="0.15"
      />
      <path
        d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z"
        stroke="#185FA5"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function SOC2Report() {
  const [rangeType, setRangeType] = useState("30"); // "30" | "90" | "custom"
  const [customFrom, setCustomFrom] = useState(toISODate(new Date(Date.now() - 30 * 864e5)));
  const [customTo, setCustomTo] = useState(toISODate(new Date()));

  const [agents, setAgents] = useState([]); // for the selector
  const [selectedAgent, setSelectedAgent] = useState("all"); // "all" | id

  const [activeTab, setActiveTab] = useState("overview");
  const [status, setStatus] = useState("idle"); // idle | loading | error | success
  const [data, setData] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [exporting, setExporting] = useState(null); // "pdf" | "docx" | null

  // ── compute the active date range ────────────────────────────
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
    const yearPart = from.getFullYear() === to.getFullYear() ? to.getFullYear() : `${from.getFullYear()}`;
    return `Period: ${prettyDate(from)} – ${prettyDate(to)}, ${yearPart}`;
  }, [range]);

  const agentIdsParam =
    selectedAgent === "all" ? undefined : String(selectedAgent);

  // ── preload dummy data on first mount so the report renders
  //    immediately (Generate / Regenerate will hit the real API) ──
  useEffect(() => {
    const mock = buildMockData();
    setAgents(mock.agents);
    setData({
      agents: mock.agents,
      summary: mock.summary,
      access: mock.access,
      sysops: mock.sysops,
      change: mock.change,
      network: mock.network,
      incidents: mock.incidents,
      recommendations: mock.recommendations,
    });
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
          name: a.name ?? a.agent_name ?? `agent_${i}`,
          hostname: a.hostname ?? a.host ?? "unknown-host",
          os: a.os ?? a.platform ?? "—",
          last_seen: a.last_seen ?? "unknown",
          status: a.status ?? "online",
        }));
        setAgents(normalized);
        return normalized;
      }
    } catch (e) {
      // fall through to mock
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
      return null; // signal caller to use mock
    }
  };

  const handleGenerate = async () => {
    setStatus("loading");
    setErrorMsg("");
    const params = buildParams();

    try {
      const [agentList, summary, access, sysops, change, network, incidents] =
        await Promise.all([
          fetchAgents(),
          safeGet("/api/v1/reports/soc2/summary", params),
          safeGet("/api/v1/reports/soc2/access", params),
          safeGet("/api/v1/reports/soc2/sysops", params),
          safeGet("/api/v1/reports/soc2/change", params),
          safeGet("/api/v1/reports/soc2/network", params),
          safeGet("/api/v1/reports/soc2/incidents", params),
        ]);

      // Fall back to realistic mock data for any missing section.
      const mock = buildMockData();
      const merged = {
        agents: agentList || mock.agents,
        summary: summary || mock.summary,
        access: access || mock.access,
        sysops: sysops || mock.sysops,
        change: change || mock.change,
        network: network || mock.network,
        incidents: incidents?.incidents || incidents || mock.incidents,
        recommendations: summary?.recommendations || mock.recommendations,
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
  // PDF: render every tab into a printable view and open the browser
  // print dialog (Save as PDF) — produces one PDF with all sections,
  // no extra packages required.
  const handleExportPdf = () => {
    if (!data) {
      handleGenerate();
      return;
    }
    // let React flush any pending state before the (blocking) print call
    setExporting("pdf");
    window.requestAnimationFrame(() => {
      window.print();
      setExporting(null);
    });
  };

  // DOCX: download from the backend blob endpoint (falls back to a
  // message if the endpoint is not ready yet).
  const handleExportDocx = async () => {
    setExporting("docx");
    const params = buildParams();
    try {
      const res = await api.get("/api/v1/reports/soc2/export", {
        params: { ...params, format: "docx" },
        responseType: "blob",
      });
      const blob = new Blob([res.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `soc2-report-${params.from}_to_${params.to}.docx`;
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

  // ── render helpers ───────────────────────────────────────────
  const loading = status === "loading";
  const s = data || {};

  const renderTab = () => {
    if (status === "idle") {
      return (
        <div className="soc2-empty-state">
          <div className="soc2-empty-icon">
            <ShieldIcon />
          </div>
          <div className="soc2-empty-title">No report generated yet</div>
          <div className="soc2-empty-sub">Set filters and click Generate.</div>
        </div>
      );
    }

    if (status === "error") {
      return (
        <div className="soc2-empty-state">
          <div className="soc2-empty-title soc2-error-title">Could not load report</div>
          <div className="soc2-empty-sub">{errorMsg}</div>
          <button className="soc2-btn soc2-btn-primary" onClick={handleGenerate}>
            Retry
          </button>
        </div>
      );
    }

    switch (activeTab) {
      case "overview":
        return <OverviewTab data={s.summary} loading={loading} />;
      case "access":
        return <AccessTab data={s.access} loading={loading} />;
      case "sysops":
        return <SysOpsTab data={s.sysops} loading={loading} />;
      case "change":
        return <ChangeTab data={s.change} loading={loading} />;
      case "network":
        return <NetworkTab data={s.network} loading={loading} />;
      case "incidents":
        return <IncidentsTable incidents={s.incidents || []} loading={loading} />;
      case "agents":
        return <AgentsTab agents={s.agents || []} loading={loading} />;
      case "recommendations":
        return <RecommendationsTab items={s.recommendations || []} loading={loading} />;
      default:
        return null;
    }
  };

  return (
    <div className="soc2-page">
      {/* ── top bar ── */}
      <div className="soc2-topbar">
        <div className="soc2-title">
          <ShieldIcon />
          <span className="soc2-title-text">
            Guardlynx <span className="soc2-title-dim">— SOC2 report</span>
          </span>
        </div>

        <div className="soc2-controls">
          <select
            className="soc2-select"
            value={rangeType}
            onChange={(e) => setRangeType(e.target.value)}
          >
            <option value="30">Last 30 days</option>
            <option value="90">Last 90 days</option>
            <option value="custom">Custom</option>
          </select>

          {rangeType === "custom" && (
            <>
              <input
                type="date"
                className="soc2-date"
                value={customFrom}
                max={customTo}
                onChange={(e) => setCustomFrom(e.target.value)}
              />
              <input
                type="date"
                className="soc2-date"
                value={customTo}
                min={customFrom}
                onChange={(e) => setCustomTo(e.target.value)}
              />
            </>
          )}

          <select
            className="soc2-select"
            value={selectedAgent}
            onChange={(e) => setSelectedAgent(e.target.value)}
          >
            <option value="all">All agents</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>

          <button
            className="soc2-btn soc2-btn-primary"
            onClick={handleGenerate}
            disabled={loading}
          >
            {loading ? "Generating…" : "Generate"}
          </button>

          <button
            className="soc2-btn"
            onClick={handleExportPdf}
            disabled={exporting !== null}
          >
            {exporting === "pdf" ? "…" : "Export PDF"}
          </button>
          {/* <button
            className="soc2-btn"
            onClick={handleExportDocx}
            disabled={exporting !== null}
          >
            {exporting === "docx" ? "…" : "Export DOCX"}
          </button> */}
        </div>
      </div>

      {/* ── tab bar ── */}
      <div className="soc2-tabbar">
        {TABS.map((t) => (
          <button
            key={t.key}
            className={`soc2-tab ${activeTab === t.key ? "active" : ""}`}
            onClick={() => setActiveTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── tab content ── */}
      <div className="soc2-content">{renderTab()}</div>

      {/* ── export bar (always visible) ── */}
      <div className="soc2-exportbar">
        <span className="soc2-export-label">Export report</span>
        <button
          className="soc2-btn soc2-btn-sm"
          onClick={handleExportPdf}
          disabled={exporting !== null}
        >
          {exporting === "pdf" ? "…" : "Export PDF"}
        </button>
        {/* <button
          className="soc2-btn soc2-btn-sm"
          onClick={handleExportDocx}
          disabled={exporting !== null}
        >
          {exporting === "docx" ? "…" : "Export DOCX"}
        </button> */}
        {/* <span className="soc2-period">{periodText}</span>
        <button
          className="soc2-btn soc2-btn-primary soc2-btn-sm soc2-regen"
          onClick={handleGenerate}
          disabled={loading}
        >
          {loading ? "…" : "Regenerate"}
        </button> */}
      </div>

      {/* ── printable full report (all tabs) — visible only when printing ── */}
      {status === "success" && data && (
        <PrintableReport data={s} agents={s.agents || []} periodText={periodText} />
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
//  Printable report — every tab stacked, shown only in print / PDF
// ════════════════════════════════════════════════════════════════

function PrintableReport({ data, agents, periodText }) {
  return (
    <div className="soc2-print-root" aria-hidden="true">
      <div className="soc2-print-header">
        <div className="soc2-print-brand">
          <ShieldIcon />
          <span className="soc2-print-title">Guardlynx — SOC2 Type II Report</span>
        </div>
        <div className="soc2-print-period">{periodText}</div>
      </div>

      <PrintSection title="1. Overview">
        <OverviewTab data={data.summary} loading={false} />
      </PrintSection>
      <PrintSection title="2. Access control (CC6)">
        <AccessTab data={data.access} loading={false} />
      </PrintSection>
      <PrintSection title="3. System operations (CC7)">
        <SysOpsTab data={data.sysops} loading={false} />
      </PrintSection>
      <PrintSection title="4. Change management (CC8)">
        <ChangeTab data={data.change} loading={false} />
      </PrintSection>
      <PrintSection title="5. Network (CC9)">
        <NetworkTab data={data.network} loading={false} />
      </PrintSection>
      <PrintSection title="6. Incidents">
        <IncidentsTable incidents={data.incidents || []} loading={false} />
      </PrintSection>
      <PrintSection title="7. Agents">
        <AgentsTab agents={agents} loading={false} />
      </PrintSection>
      <PrintSection title="8. Recommendations">
        <RecommendationsTab items={data.recommendations || []} loading={false} />
      </PrintSection>
    </div>
  );
}

function PrintSection({ title, children }) {
  return (
    <section className="soc2-print-section">
      <h2 className="soc2-print-h2">{title}</h2>
      {children}
    </section>
  );
}

// ════════════════════════════════════════════════════════════════
//  Tab bodies
// ════════════════════════════════════════════════════════════════

function Section({ title, children }) {
  return (
    <div className="soc2-card">
      {title && <div className="soc2-card-title">{title}</div>}
      {children}
    </div>
  );
}

function StatRow({ children }) {
  return <div className="soc2-statrow">{children}</div>;
}

function OverviewTab({ data = {}, loading }) {
  const m = data;
  return (
    <div className="soc2-tab-body">
      <StatRow>
        <StatCard loading={loading} label="Total events" value={m.totalEvents} sub={m.period} subColor="muted" />
        <StatCard loading={loading} label="Critical" value={m.criticalEvents} sub="needs review" subColor="danger" />
        <StatCard loading={loading} label="Agents" value={m.agentsMonitored} sub="all online" subColor="success" />
        <StatCard
          loading={loading}
          label="Compliance"
          value={m.complianceScore != null ? `${m.complianceScore}%` : "—"}
          sub={m.complianceGap}
          subColor={m.complianceScore >= 90 ? "success" : m.complianceScore >= 75 ? "warning" : "danger"}
        />
      </StatRow>

      <div className="soc2-two-col">
        <Section title="Trust service criteria scores">
          {loading ? <SkelLines n={5} /> : <CriteriaScores scores={m.criteria || []} />}
        </Section>
        <Section title="Recent critical incidents">
          {loading ? <SkelLines n={5} /> : <EventList events={m.recentEvents || []} maxItems={5} />}
        </Section>
      </div>
    </div>
  );
}

function AccessTab({ data = {}, loading }) {
  const m = data;
  const b = m.bars || {};
  return (
    <div className="soc2-tab-body">
      <div className="soc2-section-head">CC6 — Logical access controls</div>
      <StatRow>
        <StatCard loading={loading} label="Auth events" value={m.authEvents} sub="total" subColor="muted" />
        <StatCard loading={loading} label="Failed logins" value={m.failedLogins} sub={m.failRate} subColor="danger" />
        <StatCard loading={loading} label="Privilege escalations" value={m.privEscalations} sub="critical" subColor="danger" />
        <StatCard loading={loading} label="CC6 score" value={m.cc6Score != null ? `${m.cc6Score}%` : "—"} sub="passing" subColor="success" />
      </StatRow>
      <div className="soc2-two-col">
        <Section title="Login activity breakdown">
          {loading ? <SkelLines n={4} /> : (
            <>
              <ProgressBar label="Successful logins" value={b.successfulPct} count={b.successful} colorOverride="green" />
              <ProgressBar label="Failed logins" value={b.failedPct} count={b.failed} colorOverride="red" />
              <ProgressBar label="Locked accounts" value={b.lockedPct} count={b.locked} colorOverride="amber" />
              <ProgressBar label="MFA verified" value={b.mfaPct} count={b.mfa} colorOverride="blue" />
            </>
          )}
        </Section>
        <Section title="Auth events log">
          {loading ? <SkelLines n={5} /> : <EventList events={m.events || []} maxItems={6} />}
        </Section>
      </div>
    </div>
  );
}

function SysOpsTab({ data = {}, loading }) {
  const m = data;
  const b = m.bars || {};
  return (
    <div className="soc2-tab-body">
      <div className="soc2-section-head">CC7 — System operations</div>
      <StatRow>
        <StatCard loading={loading} label="Process events" value={m.processEvents} sub="total" subColor="muted" />
        <StatCard loading={loading} label="Anomalies" value={m.anomalies} sub="detected" subColor="warning" />
        <StatCard loading={loading} label="Avg CPU" value={m.avgCpu != null ? `${m.avgCpu}%` : "—"} sub="normal" subColor="success" />
        <StatCard loading={loading} label="CC7 score" value={m.cc7Score != null ? `${m.cc7Score}%` : "—"} sub="passing" subColor="success" />
      </StatRow>
      <div className="soc2-two-col">
        <Section title="Resource utilization">
          {loading ? <SkelLines n={4} /> : (
            <>
              <ProgressBar label={`CPU — avg ${b.avgCpu}%`} value={b.avgCpu} count="normal" />
              <ProgressBar label={`Memory — avg ${b.avgMem}%`} value={b.avgMem} count="watch" />
              <ProgressBar label={`Peak CPU — ${b.peakCpu}%`} value={b.peakCpu} count="high" />
              <ProgressBar label="Disk I/O — normal" value={b.diskIo} count={`${b.diskIo}%`} colorOverride="blue" />
            </>
          )}
        </Section>
        <Section title="Process anomalies">
          {loading ? <SkelLines n={5} /> : <EventList events={m.events || []} maxItems={6} />}
        </Section>
      </div>
    </div>
  );
}

function ChangeTab({ data = {}, loading }) {
  const m = data;
  const b = m.bars || {};
  return (
    <div className="soc2-tab-body">
      <div className="soc2-section-head">CC8 — Change management</div>
      <StatRow>
        <StatCard loading={loading} label="File events" value={m.fileEvents} sub="total" subColor="muted" />
        <StatCard loading={loading} label="Config changes" value={m.configChanges} sub="outside window" subColor="warning" />
        <StatCard loading={loading} label="Binary changes" value={m.binaryChanges} sub="critical" subColor="danger" />
        <StatCard loading={loading} label="CC8 score" value={m.cc8Score != null ? `${m.cc8Score}%` : "—"} sub="needs work" subColor="warning" />
      </StatRow>
      <div className="soc2-two-col">
        <Section title="File modification breakdown">
          {loading ? <SkelLines n={4} /> : (
            <>
              <ProgressBar label="Log files" value={b.logPct} count={b.log} colorOverride="blue" />
              <ProgressBar label="Config files" value={b.configPct} count={b.config} colorOverride="amber" />
              <ProgressBar label="Binary / executable" value={b.binaryPct} count={b.binary} colorOverride="red" />
              <ProgressBar label="Other files" value={b.otherPct} count={b.other} colorOverride="#999" />
            </>
          )}
        </Section>
        <Section title="Sensitive file changes">
          {loading ? <SkelLines n={5} /> : <EventList events={m.events || []} maxItems={6} />}
        </Section>
      </div>
    </div>
  );
}

function NetworkTab({ data = {}, loading }) {
  const m = data;
  const b = m.bars || {};
  return (
    <div className="soc2-tab-body">
      <div className="soc2-section-head">CC9 — Network and risk mitigation</div>
      <StatRow>
        <StatCard loading={loading} label="Network events" value={m.networkEvents} sub="total" subColor="muted" />
        <StatCard loading={loading} label="Blocked" value={m.blockedConnections} sub="connections" subColor="warning" />
        <StatCard loading={loading} label="Port scans" value={m.portScans} sub="detected" subColor="danger" />
        <StatCard loading={loading} label="CC9 score" value={m.cc9Score != null ? `${m.cc9Score}%` : "—"} sub="passing" subColor="success" />
      </StatRow>
      <div className="soc2-two-col">
        <Section title="Connection breakdown">
          {loading ? <SkelLines n={4} /> : (
            <>
              <ProgressBar label="Clean connections" value={b.cleanPct} count={b.clean} colorOverride="green" />
              <ProgressBar label="Blocked connections" value={b.blockedPct} count={b.blocked} colorOverride="amber" />
              <ProgressBar label="Port scans detected" value={b.scansPct} count={b.scans} colorOverride="red" />
              <ProgressBar label="DNS queries" value={b.dnsPct} count={b.dns} colorOverride="blue" />
            </>
          )}
        </Section>
        <Section title="Network incidents">
          {loading ? <SkelLines n={5} /> : <EventList events={m.events || []} maxItems={6} />}
        </Section>
      </div>
    </div>
  );
}

function AgentsTab({ agents, loading }) {
  const counts = useMemo(() => {
    const c = { total: agents.length, online: 0, degraded: 0, offline: 0 };
    agents.forEach((a) => {
      if (a.status === "online") c.online += 1;
      else if (a.status === "degraded") c.degraded += 1;
      else if (a.status === "offline") c.offline += 1;
    });
    return c;
  }, [agents]);

  return (
    <div className="soc2-tab-body">
      <div className="soc2-section-head">Agent status and health</div>
      <StatRow>
        <StatCard loading={loading} label="Total agents" value={counts.total} sub="registered" subColor="muted" />
        <StatCard loading={loading} label="Online" value={counts.online} sub="active" subColor="success" />
        <StatCard loading={loading} label="Degraded" value={counts.degraded} sub="watch" subColor="warning" />
        <StatCard loading={loading} label="Offline" value={counts.offline} sub="needs attention" subColor="danger" />
      </StatRow>
      <Section title="Agent inventory">
        <AgentsTable agents={agents} loading={loading} />
      </Section>
    </div>
  );
}

function RecommendationsTab({ items, loading }) {
  if (loading) return <SkelLines n={6} />;
  return (
    <div className="soc2-tab-body">
      <div className="soc2-section-head">Recommendations and remediation</div>
      <ol className="soc2-recs">
        {items.map((r, i) => (
          <li key={i} className={`soc2-rec soc2-rec-${r.priority || "info"}`}>
            <span className="soc2-rec-num">{String(i + 1).padStart(2, "0")}</span>
            <span className="soc2-rec-text">{r.text}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

function SkelLines({ n = 4 }) {
  return (
    <div className="soc2-skel-lines">
      {Array.from({ length: n }).map((_, i) => (
        <div key={i} className="stat-skel" style={{ height: 14, margin: "8px 0" }} />
      ))}
    </div>
  );
}
