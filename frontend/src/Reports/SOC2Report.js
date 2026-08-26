import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import "./SOC2Report.css";

import StatCard from "./components/StatCard";
import ProgressBar from "./components/ProgressBar";
import EventList from "./components/EventList";
import IncidentsTable from "./components/IncidentsTable";
import AgentsTable from "./components/AgentsTable";
import CriteriaScores from "./components/CriteriaScores";
import TimeSeriesChart from "./components/TimeSeriesChart";

import { fetchSoc2Report, fetchAgents, SOC2_SECTIONS } from "./soc2Api";
import { buildSoc2View, fmtInt, fmtIst } from "./soc2Transform";
import { lastHoursInputs, istInputToApi } from "./timeRange";

// ─── controls ──────────────────────────────────────────────────

// Quick ranges, in hours. Anything past two days is bucketed by day by default,
// because an hourly series over a month is unreadable.
const PRESET_HOURS = [12, 24, 48, 168, 720];

function presetLabel(hours) {
  if (hours < 24) return `Last ${hours} hours`;
  const days = hours / 24;
  return days === 1 ? "Last 24 hours" : `Last ${days} days`;
}

function defaultBucket(hours) {
  return hours > 48 ? "day" : "hour";
}

/** Length in hours of a window given as two IST datetime-local values. */
function spanHours(fromLocal, toLocal) {
  const from = Date.parse(`${fromLocal}:00Z`);
  const to = Date.parse(`${toLocal}:00Z`);
  if (Number.isNaN(from) || Number.isNaN(to) || to <= from) return 12;
  return (to - from) / (60 * 60 * 1000);
}

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "auth", label: "Access control" },
  { key: "process", label: "System ops" },
  { key: "file", label: "Change mgmt" },
  { key: "network", label: "Network" },
  { key: "usb", label: "Removable media" },
  { key: "incidents", label: "Incidents" },
  { key: "agents", label: "Agents" },
  { key: "recommendations", label: "Recommendations" },
];

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

function isCanceled(err) {
  return Boolean(err) && (err.code === "ERR_CANCELED" || err.name === "CanceledError");
}

export default function SOC2Report() {
  const initialWindow = useMemo(() => lastHoursInputs(12), []);

  // `?agent=<name>` scopes the report on arrival — that is how the dashboard's
  // agent table hands an agent over. `agent_name` is accepted too, for URLs
  // written by hand against the API's own parameter name.
  const [searchParams, setSearchParams] = useSearchParams();
  const initialAgent = useMemo(
    () => (searchParams.get("agent") || searchParams.get("agent_name") || "").trim(),
    // read once, on arrival: later edits come from the controls, not the URL
    // eslint-disable-next-line react-hooks/exhaustive-deps
    []
  );

  // `?from=`/`?to=` (IST datetime-local values, "YYYY-MM-DDTHH:mm") arrive with
  // the agent when the dashboard's "Create SOC2 report" form hands a window over.
  // Anything malformed falls back to the default last-12-hours window.
  const initialRange = useMemo(() => {
    const from = (searchParams.get("from") || "").trim();
    const to = (searchParams.get("to") || "").trim();
    const shape = /^d{4}-d{2}-d{2}Td{2}:d{2}$/;
    if (shape.test(from) && shape.test(to) && from < to) return { from, to, custom: true };
    return { from: initialWindow.from, to: initialWindow.to, custom: false };
    // read once, on arrival: later edits come from the controls, not the URL
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const [agentName, setAgentName] = useState(initialAgent);
  // a window that came in on the URL is by definition not one of the presets
  const [preset, setPreset] = useState(initialRange.custom ? "custom" : "12");
  const [fromLocal, setFromLocal] = useState(initialRange.from);
  const [toLocal, setToLocal] = useState(initialRange.to);
  const [bucket, setBucket] = useState(() =>
    defaultBucket(spanHours(initialRange.from, initialRange.to))
  );

  const [agents, setAgents] = useState([]);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");
  const [status, setStatus] = useState("idle"); // idle | loading | success | error
  const [report, setReport] = useState(null);
  // The parameters the report on screen was actually built from — the controls
  // can be edited without pressing Generate, so they are not the same thing.
  const [loadedParams, setLoadedParams] = useState(null);
  // One entry per request: "loading" | "ok" | "error". This is what the loader
  // strip renders, and what tells a still-loading domain from a failed one.
  const [sectionStatus, setSectionStatus] = useState({});
  const [sectionErrors, setSectionErrors] = useState([]);
  const [errorMsg, setErrorMsg] = useState("");
  const [exporting, setExporting] = useState(false);

  const abortRef = useRef(null);
  const runRef = useRef(0);

  /** The current controls as the API's parameter object. */
  const toParams = useCallback(
    () => ({
      agentName: agentName.trim(),
      fromDt: istInputToApi(fromLocal, "00"),
      toDt: istInputToApi(toLocal, "59"),
      bucket,
    }),
    [agentName, fromLocal, toLocal, bucket]
  );

  /**
   * Run the five reports for one window.
   *
   * Each request has its own loader: the strip under the toolbar shows all five
   * spinning, and every domain is rebuilt the moment its own response lands, so
   * the fast reports are readable while the slow ones are still running.
   */
  const load = useCallback(async (params) => {
    if (!params.fromDt || !params.toDt) {
      setErrorMsg("Pick a valid From and To date/time.");
      setStatus("error");
      return;
    }
    if (params.fromDt >= params.toDt) {
      setErrorMsg("From must be before To.");
      setStatus("error");
      return;
    }

    if (abortRef.current) abortRef.current.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    // A superseded run must not write over the current one's state.
    const runId = runRef.current + 1;
    runRef.current = runId;
    const isCurrent = () => runRef.current === runId;

    setStatus("loading");
    setErrorMsg("");
    setSectionErrors([]);
    setSectionStatus(SOC2_SECTIONS.reduce((acc, s) => ({ ...acc, [s]: "loading" }), {}));
    setLoadedParams(params);
    // the shell, with every domain marked pending, so loaders show immediately
    setReport(buildSoc2View({}, params, { pending: SOC2_SECTIONS }));

    const arrived = {};
    const waiting = new Set(SOC2_SECTIONS);

    try {
      const { errors } = await fetchSoc2Report(params, {
        signal: controller.signal,
        onSection: ({ section, data, error }) => {
          if (!isCurrent()) return;
          waiting.delete(section);
          if (data) arrived[section] = data;
          setSectionStatus((prev) => ({ ...prev, [section]: error ? "error" : "ok" }));
          setReport(buildSoc2View(arrived, params, { pending: Array.from(waiting) }));
        },
      });
      if (!isCurrent()) return;

      setSectionErrors(errors);

      // Every one of the five failed — there is nothing to render.
      if (errors.length === SOC2_SECTIONS.length) {
        setReport(null);
        setErrorMsg(errors[0].message);
        setStatus("error");
        return;
      }

      setStatus("success");
    } catch (err) {
      if (isCanceled(err) || !isCurrent()) return;
      setErrorMsg(err.message || "Failed to generate the report.");
      setStatus("error");
    }
  }, []);

  // First render loads the default window (last 12 hours) for whichever agent
  // the URL named — every agent when it named none — so the page shows real data
  // without waiting on a click.
  useEffect(() => {
    load({
      agentName: initialAgent,
      fromDt: istInputToApi(initialRange.from, "00"),
      toDt: istInputToApi(initialRange.to, "59"),
      bucket: defaultBucket(spanHours(initialRange.from, initialRange.to)),
    });
    return () => {
      if (abortRef.current) abortRef.current.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The agent picker's suggestions and the Agents tab. Failure here is not
  // fatal: the field stays free-text, and an empty name means "all agents".
  useEffect(() => {
    let alive = true;
    setAgentsLoading(true);
    fetchAgents()
      .then((list) => {
        if (alive) setAgents(list);
      })
      .catch(() => {})
      .finally(() => {
        if (alive) setAgentsLoading(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  const applyPreset = (hours) => {
    const next = lastHoursInputs(hours);
    setPreset(String(hours));
    setFromLocal(next.from);
    setToLocal(next.to);
    setBucket(defaultBucket(hours));
  };

  /**
   * Mirror the scope — agent and window — into the URL, so a refresh or a shared
   * link keeps it, and so a window that arrived on the URL cannot go stale once
   * the controls move on.
   */
  const syncUrl = useCallback(
    (name, from, to) => {
      const next = new URLSearchParams(searchParams);
      next.delete("agent_name"); // normalise the alias away
      if (name) next.set("agent", name);
      else next.delete("agent");
      if (from && to) {
        next.set("from", from);
        next.set("to", to);
      }
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams]
  );

  const onSubmit = (e) => {
    e.preventDefault();
    const params = toParams();
    syncUrl(params.agentName, fromLocal, toLocal);
    load(params);
  };

  /**
   * Clicking a row in the Agents table scopes the whole report to that agent —
   * its name becomes `agent_name` on all five requests. Clicking the row that is
   * already scoped clears the filter and goes back to every agent.
   */
  const selectAgent = (agent) => {
    const next = agentName.trim() === agent.name ? "" : agent.name;
    setAgentName(next);
    syncUrl(next, fromLocal, toLocal);
    load({ ...toParams(), agentName: next });
  };

  /** Left/right (and Home/End) move between tabs, as a tablist should. */
  const onTabKeyDown = (e) => {
    const keys = TABS.map((t) => t.key);
    const i = keys.indexOf(activeTab);
    let next = null;
    if (e.key === "ArrowRight") next = keys[(i + 1) % keys.length];
    else if (e.key === "ArrowLeft") next = keys[(i - 1 + keys.length) % keys.length];
    else if (e.key === "Home") next = keys[0];
    else if (e.key === "End") next = keys[keys.length - 1];
    if (!next) return;
    e.preventDefault();
    setActiveTab(next);
    const el = document.getElementById(`soc2-tab-${next}`);
    if (el) el.focus();
  };

  const handleExportPdf = () => {
    if (!report) return;
    setExporting(true);
    window.requestAnimationFrame(() => {
      window.print();
      setExporting(false);
    });
  };

  const loading = status === "loading";
  const periodText = `${fromLocal.replace("T", " ")} – ${toLocal.replace("T", " ")} IST`;

  // What the report on screen covers: the loaded parameters once there is a
  // report, the pending controls before that.
  const scopeAgent = loadedParams
    ? loadedParams.agentName || "All agents"
    : agentName.trim() || "All agents";
  const scopeWindow = loadedParams
    ? `${fmtIst(loadedParams.fromDt)} – ${fmtIst(loadedParams.toDt)} IST`
    : periodText;
  const scopeBucket = `${loadedParams ? loadedParams.bucket : bucket}ly buckets`;
  const scopeText = `${scopeAgent} · ${scopeWindow} · ${scopeBucket}`;
  // How many of the five requests are still open. Each tab shows its own state;
  // this is only for the one-line count next to the scope.
  const pendingCount = report ? report.summary.pendingCount : 0;

  const renderTab = () => {
    if (status === "error" && !report) {
      return (
        <div className="soc2-empty-state">
          <div className="soc2-empty-title soc2-error-title">Could not load report</div>
          <div className="soc2-empty-sub">{errorMsg}</div>
          <button className="soc2-btn soc2-btn-primary" onClick={() => load(toParams())}>
            Retry
          </button>
        </div>
      );
    }

    if (!report) {
      return (
        <div className="soc2-empty-state">
          <div className="soc2-empty-icon">
            <ShieldIcon />
          </div>
          <div className="soc2-empty-title">{loading ? "Generating report…" : "No report generated yet"}</div>
          <div className="soc2-empty-sub">Set the agent and window, then click Generate.</div>
        </div>
      );
    }

    // How many of the five are still open — each tab shows its own loader off
    // this, rather than blanking the whole page while one request finishes.
    const pending = report.summary.pendingCount;
    const nothingYet = report.summary.loadedCount === 0;

    switch (activeTab) {
      case "overview":
        return (
          <OverviewTab
            summary={report.summary}
            views={report.views}
            onOpenDomain={setActiveTab}
            loading={nothingYet && pending > 0}
          />
        );
      case "incidents":
        return (
          <div className="soc2-tab-body">
            <PendingNote pending={pending} what="incidents" />
            <IncidentsTable incidents={report.incidents} loading={nothingYet && pending > 0} />
          </div>
        );
      case "agents":
        return (
          <AgentsTab
            agents={agents}
            loading={agentsLoading}
            onSelect={selectAgent}
            selectedName={agentName.trim()}
          />
        );
      case "recommendations":
        return (
          <div className="soc2-tab-body">
            <PendingNote pending={pending} what="findings" />
            <RecommendationsTab items={report.recommendations} loading={nothingYet && pending > 0} />
          </div>
        );
      default:
        return <SectionView view={report.views[activeTab]} />;
    }
  };

  return (
    <div className="soc2-page">
      {/* ── top bar ── */}
      <div className="soc2-topbar">
        <div className="soc2-title">
          {/* the app header already carries the brand, so this names the page */}
          <span className="soc2-title-icon">
            <ShieldIcon />
          </span>
          <span className="soc2-title-text">
            <span className="soc2-title-main">SOC2 report</span>
            <span className="soc2-title-sub">
              Trust service criteria evidence · times in IST
            </span>
          </span>
        </div>

        <form className="soc2-controls" onSubmit={onSubmit}>
          <label className="soc2-field">
            <span className="soc2-field-label">Agent</span>
            <input
              className="soc2-input"
              type="text"
              list="soc2-agent-names"
              value={agentName}
              onChange={(e) => setAgentName(e.target.value)}
              placeholder="All agents"
              autoComplete="off"
            />
          </label>
          <datalist id="soc2-agent-names">
            {agents.map((a) => (
              <option key={a.id} value={a.name} />
            ))}
          </datalist>

          <label className="soc2-field">
            <span className="soc2-field-label">Range</span>
            <select
              className="soc2-select"
              value={preset}
              onChange={(e) =>
                e.target.value === "custom" ? setPreset("custom") : applyPreset(Number(e.target.value))
              }
            >
              {PRESET_HOURS.map((h) => (
                <option key={h} value={String(h)}>
                  {presetLabel(h)}
                </option>
              ))}
              <option value="custom">Custom…</option>
            </select>
          </label>

          {/* the two date fields are the rare case, so they stay out of the way
              until the range is actually set by hand */}
          {preset === "custom" && (
            <>
              <label className="soc2-field">
                <span className="soc2-field-label">From (IST)</span>
                <input
                  type="datetime-local"
                  className="soc2-date"
                  value={fromLocal}
                  max={toLocal}
                  onChange={(e) => setFromLocal(e.target.value)}
                />
              </label>

              <label className="soc2-field">
                <span className="soc2-field-label">To (IST)</span>
                <input
                  type="datetime-local"
                  className="soc2-date"
                  value={toLocal}
                  min={fromLocal}
                  onChange={(e) => setToLocal(e.target.value)}
                />
              </label>

              <label className="soc2-field">
                <span className="soc2-field-label">Buckets</span>
                <select
                  className="soc2-select"
                  value={bucket}
                  onChange={(e) => setBucket(e.target.value)}
                >
                  <option value="hour">Hourly</option>
                  <option value="day">Daily</option>
                </select>
              </label>
            </>
          )}

          <div className="soc2-actions">
            <button className="soc2-btn soc2-btn-primary" type="submit" disabled={loading}>
              {loading ? "Generating…" : "Generate"}
            </button>
            <button
              className="soc2-btn"
              type="button"
              onClick={handleExportPdf}
              disabled={!report || exporting}
            >
              {exporting ? "…" : "Export PDF"}
            </button>
          </div>
        </form>
      </div>

      <div className="soc2-scope">
        <span className="soc2-scope-label">Agent</span>
        <strong className="soc2-scope-agent">{scopeAgent}</strong>
        <span className="soc2-scope-rest">
          {scopeWindow} · {scopeBucket}
        </span>
        {/* the per-report loaders live on the tabs; this is just the count */}
        {pendingCount > 0 && (
          <span className="soc2-scope-loading" role="status" aria-live="polite">
            <Spinner />
            Loading {pendingCount} of {SOC2_SECTIONS.length} reports…
          </span>
        )}
      </div>

      {/* A refresh that failed outright, with an earlier report still on screen. */}
      {status === "error" && report && (
        <div className="soc2-errorbar" role="alert">
          <span>{errorMsg} Showing the last window that loaded.</span>
          <button className="soc2-btn soc2-btn-sm" type="button" onClick={() => load(toParams())}>
            Retry
          </button>
        </div>
      )}

      {/* Sections that failed while others loaded — the report still renders. */}
      {sectionErrors.length > 0 && status !== "loading" && (
        <div className="soc2-warnbar" role="alert">
          {sectionErrors.map((e) => (
            <div className="soc2-warnbar-row" key={e.section}>
              <strong>{e.label}</strong> report unavailable
              {e.status ? ` (HTTP ${e.status})` : ""} — {e.message}
            </div>
          ))}
        </div>
      )}

      {/* ── tab bar — each domain tab carries its own request's state ── */}
      <div className="soc2-tabbar" role="tablist" aria-label="Report sections" onKeyDown={onTabKeyDown}>
        {TABS.map((t) => {
          const state = sectionStatus[t.key];
          const selected = activeTab === t.key;
          return (
            <button
              key={t.key}
              id={`soc2-tab-${t.key}`}
              role="tab"
              type="button"
              aria-selected={selected}
              aria-controls="soc2-tabpanel"
              // only the active tab is in the tab order; the arrows move between
              // them, which is how a tablist is expected to behave
              tabIndex={selected ? 0 : -1}
              className={`soc2-tab ${selected ? "active" : ""}`}
              onClick={() => setActiveTab(t.key)}
            >
              {t.label}
              {state === "loading" && <Spinner label={`${t.label} report loading`} />}
              {state === "error" && (
                <span className="soc2-tab-dot" title="This report did not load" />
              )}
            </button>
          );
        })}
      </div>

      {/* ── tab content ── */}
      <div
        className="soc2-content"
        id="soc2-tabpanel"
        role="tabpanel"
        aria-labelledby={`soc2-tab-${activeTab}`}
      >
        {renderTab()}
      </div>

      {/* ── footer: what this page is showing, in one line ── */}
      <div className="soc2-exportbar">
        <span className="soc2-period">
          {report && report.meta.generatedAt !== "—"
            ? `Generated ${report.meta.generatedAt} IST · ${scopeWindow} · ${scopeBucket}`
            : `${scopeWindow} · ${scopeBucket}`}
        </span>
      </div>

      {/* ── printable full report (all tabs) — visible only when printing ── */}
      {report && (
        <PrintableReport report={report} agents={agents} scopeText={scopeText} />
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
//  Printable report — every tab stacked, shown only in print / PDF
// ════════════════════════════════════════════════════════════════

/**
 * The printed report is read by people who did not run it — an auditor, a
 * manager, someone new to the platform. Each section therefore opens with a
 * plain-English explanation of what it shows and how to read it, and starts on
 * its own page so a section can be pulled out and circulated on its own.
 */
function printSections(report, agents) {
  return [
    {
      title: "Overview",
      lead: `Everything the agents recorded in this window, summarised across the five monitored
        domains. The compliance figure is the average of the domain scores below; each domain
        starts at 100 and loses points in proportion to how many of its events were high
        severity, matched a threat indicator, were flagged as anomalous, or failed. A domain
        that recorded nothing at all is listed but not scored — an empty window is an absence
        of evidence, not proof that the control worked.`,
      body: <OverviewTab summary={report.summary} loading={false} />,
    },
    {
      title: "Access control (CC6)",
      lead: `Who signed in, from where, and what was refused. SOC 2 criterion CC6 covers logical
        access. The evidence here is the balance of successful against failed authentication,
        the accounts and source addresses behind the failures, and every use of elevated
        (administrator or sudo) privilege in the window — each of which an auditor expects to
        tie back to an approved request.`,
      body: <SectionView view={report.views.auth} expanded />,
    },
    {
      title: "System operations (CC7)",
      lead: `What actually ran on the monitored hosts. CC7 covers system operation and
        monitoring: which programs executed, under which account, the resources they consumed,
        and anything the agent judged abnormal or matched against a threat indicator. CPU
        percentages are summed across processor cores, so figures above 100% are normal on a
        multi-core machine — the bars are drawn relative to the window's own peak.`,
      body: <SectionView view={report.views.process} expanded />,
    },
    {
      title: "Change management (CC8)",
      lead: `What changed on disk. CC8 covers change management. The evidence is which files
        were created, modified or deleted, in which directories, by which account, and which of
        those changes altered a file's contents or location in a way that warrants review.
        Unexpected changes to configuration or executable files are the ones to explain.`,
      body: <SectionView view={report.views.file} expanded />,
    },
    {
      title: "Network (CC9)",
      lead: `What the hosts talked to. CC9 covers risk mitigation at the network boundary:
        how many connections were made, to which addresses and ports, how much data moved in
        each direction, and which destinations were public rather than internal. Reconcile the
        external destinations against whatever egress is approved for these machines.`,
      body: <SectionView view={report.views.network} expanded />,
    },
    {
      title: "Removable media",
      lead: `USB drives and other removable devices: which were attached, by vendor, model and
        serial number, and how much data moved to or from them. This is the one channel by
        which data can leave a host without crossing the network, so any transfer here should
        match an authorised business need under the data-handling policy.`,
      body: <SectionView view={report.views.usb} expanded />,
    },
    {
      title: "Incidents",
      lead: `Every notable and anomalous event from the five domains, merged and listed newest
        first. "Notable" means the agent rated the event high or critical; "anomalous" means it
        departed from the host's normal pattern. Each row names the domain it came from and,
        where the agent identified one, the MITRE ATT&CK technique — the industry catalogue of
        attacker behaviours.`,
      body: <IncidentsTable incidents={report.incidents} loading={false} />,
    },
    {
      title: "Agents",
      lead: `The agents registered with the platform and the state of their connection. This is
        the coverage statement for everything above: an agent that was offline reported nothing,
        so any window overlapping its downtime has gaps that the counts in this report cannot
        show.`,
      body: <AgentsTab agents={agents} loading={false} />,
    },
    {
      title: "Recommendations",
      lead: `Findings derived from this window's own numbers, most serious first. These are
        prompts for review rather than conclusions: each one names a figure an auditor would
        expect to see explained, evidenced, or remediated before the next reporting period.`,
      body: <RecommendationsTab items={report.recommendations} loading={false} />,
    },
  ];
}

function PrintableReport({ report, agents, scopeText }) {
  const sections = printSections(report, agents);

  return (
    <div className="soc2-print-root" aria-hidden="true">
      {/* ── cover page ── */}
      <section className="soc2-print-cover">
        <div className="soc2-print-header">
          <div className="soc2-print-brand">
            <ShieldIcon />
            <span className="soc2-print-title">Guardlynx — SOC 2 evidence report</span>
          </div>
          <div className="soc2-print-period">{scopeText}</div>
        </div>

        <p className="soc2-print-lead">
          This report collects the activity the Guardlynx agents recorded for the period above,
          arranged against the SOC 2 trust service criteria. It is generated from the agents'
          own telemetry — nothing in it is entered by hand — and each section states what it
          covers and how to read it. All times are India Standard Time (UTC+5:30).
        </p>

        <div className="soc2-print-meta">
          <div>
            <span className="soc2-print-meta-key">Scope</span>
            <span className="soc2-print-meta-val">{report.meta.agentName || "All agents"}</span>
          </div>
          <div>
            <span className="soc2-print-meta-key">Generated</span>
            <span className="soc2-print-meta-val">
              {report.meta.generatedAt !== "—" ? `${report.meta.generatedAt} IST` : "—"}
            </span>
          </div>
          <div>
            <span className="soc2-print-meta-key">Events</span>
            <span className="soc2-print-meta-val">{fmtInt(report.summary.totalEvents)}</span>
          </div>
        </div>

        <div className="soc2-print-toc">
          <div className="soc2-print-toc-head">Contents</div>
          <ol className="soc2-print-toc-list">
            {sections.map((s) => (
              <li key={s.title}>{s.title}</li>
            ))}
          </ol>
        </div>
      </section>

      {sections.map((s, i) => (
        <PrintSection key={s.title} number={i + 1} title={s.title} lead={s.lead}>
          {s.body}
        </PrintSection>
      ))}
    </div>
  );
}

function PrintSection({ number, title, lead, children }) {
  return (
    <section className="soc2-print-section">
      <h2 className="soc2-print-h2">
        {number}. {title}
      </h2>
      {lead && <p className="soc2-print-lead">{lead}</p>}
      {children}
    </section>
  );
}

// ════════════════════════════════════════════════════════════════
//  Building blocks
// ════════════════════════════════════════════════════════════════

/**
 * A folded-away block — the detail that would otherwise bury the page.
 *
 * Native <details>, so it needs no state and stays keyboard- and
 * find-in-page-friendly. `open` starts it expanded; the printed report passes it
 * so paper carries the full evidence.
 */
function Disclosure({ title, hint, children, open = false }) {
  return (
    <details className="soc2-fold" open={open}>
      <summary className="soc2-fold-head">
        <span className="soc2-fold-chevron" aria-hidden="true" />
        <span className="soc2-fold-title">{title}</span>
        {hint && <span className="soc2-fold-hint">{hint}</span>}
      </summary>
      <div className="soc2-fold-body">{children}</div>
    </details>
  );
}

/** Small inline spinner, for anything that is waiting on a request. */
function Spinner({ label }) {
  return <span className="soc2-spinner" role="img" aria-label={label || "Loading"} />;
}

/**
 * "Still loading N of the five reports" — hidden once nothing is pending.
 *
 * Each request's own state lives on its tab; this only explains why a total on
 * the page is lower than it will be in a moment.
 */
function PendingNote({ pending, what = "data" }) {
  if (!pending) return null;
  return (
    <div className="soc2-note soc2-note-loading">
      <Spinner />
      Loading {pending} of {SOC2_SECTIONS.length} reports — {what} will fill in as they arrive.
    </div>
  );
}

function Section({ title, children, wide = false }) {
  return (
    <div className={`soc2-card ${wide ? "soc2-card-wide" : ""}`}>
      {title && <div className="soc2-card-title">{title}</div>}
      {children}
    </div>
  );
}

function StatRow({ children }) {
  return <div className="soc2-statrow">{children}</div>;
}

/** Top-N list from the API's {label, count} breakdowns, scaled to its own max. */
function BreakdownList({ items = [] }) {
  const max = items.reduce((m, i) => Math.max(m, Number(i.count) || 0), 0);
  if (items.length === 0) return <div className="evt-empty">Nothing recorded.</div>;

  return (
    <div className="soc2-bd-list">
      {items.map((i, idx) => {
        // The API returns real rows with an empty label (890 process events with
        // no executable path, for one). Naming them keeps the row readable
        // instead of rendering a bar against blank space.
        const blank = String(i.label == null ? "" : i.label).trim() === "";
        const label = blank ? "(not reported)" : i.label;
        return (
          <div className="soc2-bd-row" key={`${i.label}-${idx}`}>
            <span className={`soc2-bd-label ${blank ? "soc2-bd-blank" : ""}`} title={String(label)}>
              {label}
            </span>
            <span className="soc2-bd-track">
              <span
                className="soc2-bd-fill"
                style={{ width: `${max ? ((Number(i.count) || 0) / max) * 100 : 0}%` }}
              />
            </span>
            <span className="soc2-bd-count">{fmtInt(i.count)}</span>
          </div>
        );
      })}
    </div>
  );
}

/** Detail table for the row-level evidence (privileged access, transfers, …). */
function DataTable({ columns = [], rows = [], maxRows = 50 }) {
  const shown = rows.slice(0, maxRows);
  if (rows.length === 0) return <div className="evt-empty">Nothing recorded.</div>;

  return (
    <div className="inc-table-wrap">
      <table className="inc-table soc2-tbl">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key}>{c.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {shown.map((r, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c.key} title={String(r[c.key] == null ? "" : r[c.key])}>
                  {r[c.key] == null || r[c.key] === "" ? "—" : r[c.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > shown.length && (
        <div className="soc2-tbl-more">
          Showing {shown.length} of {fmtInt(rows.length)} rows.
        </div>
      )}
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

// ════════════════════════════════════════════════════════════════
//  Tab bodies
// ════════════════════════════════════════════════════════════════

/**
 * One domain report (auth / process / file / network / usb). Every section comes
 * out of soc2Transform in the same shape, so this renders all five.
 */
function SectionView({ view, expanded = false }) {
  if (!view) return <SkelLines n={6} />;

  // This domain's own request is still open: skeletons in place of its numbers,
  // so the wait is visible on the tab itself and not only on the loader strip.
  if (view.pending) {
    return (
      <div className="soc2-tab-body">
        <div className="soc2-section-head">{view.heading}</div>
        <div className="soc2-note soc2-note-loading">
          <Spinner />
          Loading this report…
        </div>
        <StatRow>
          {[0, 1, 2, 3].map((i) => (
            <StatCard key={i} loading />
          ))}
        </StatRow>
        <div className="soc2-two-col">
          <Section title="">
            <SkelLines n={4} />
          </Section>
          <Section title="">
            <SkelLines n={5} />
          </Section>
        </div>
      </div>
    );
  }

  // The domain's request failed. Showing its zeroed stats would read as a clean
  // control, so the numbers are withheld entirely.
  if (view.unavailable) {
    return (
      <div className="soc2-tab-body">
        <div className="soc2-section-head">{view.heading}</div>
        <div className="soc2-note">
          This domain's report did not load, so it is excluded from the scores and the
          incident list — treat the window as having no evidence for this control rather
          than as a clean result.{" "}
          <span className="soc2-screen-only">Click Generate to try the window again.</span>
        </div>
      </div>
    );
  }

  // Past the two branches above the payload is in hand, so nothing here is in a
  // loading state.
  const charts = (view.charts || []).filter((c) => c.series.some((s) => s.data.length > 0));

  return (
    <div className="soc2-tab-body">
      <div className="soc2-section-head">{view.heading}</div>

      <StatRow>
        {view.stats.map((s) => (
          <StatCard key={s.label} label={s.label} value={s.value} sub={s.sub} subColor={s.subColor} />
        ))}
      </StatRow>

      {view.total === 0 && (
        <div className="soc2-note">No events of this type were recorded in the selected window.</div>
      )}

      <div className="soc2-two-col">
        <Section title={view.bars.title}>
          {view.bars.items.map((b) => (
            <ProgressBar
              key={b.label}
              label={b.label}
              value={b.value}
              count={b.count}
              colorOverride={b.colorOverride}
            />
          ))}
        </Section>
        <Section title={view.events.title}>
          <EventList events={view.events.items} maxItems={7} />
        </Section>
      </div>

      {charts.map((c) => (
        <Section key={c.title} title={c.title} wide>
          <TimeSeriesChart series={c.series} yMax={c.yMax} unit={c.unit} height={220} />
        </Section>
      ))}

      {/* The detail is the bulk of the page, so it stays folded away until it is
          asked for — the printed report opens everything instead. */}
      {view.breakdowns.length > 0 && (
        <Disclosure
          title="Breakdowns"
          hint={`${view.breakdowns.length} lists`}
          open={expanded}
        >
          <div className="soc2-card-grid">
            {view.breakdowns.map((b) => (
              <Section key={b.title} title={b.title}>
                <BreakdownList items={b.items} />
              </Section>
            ))}
          </div>
        </Disclosure>
      )}

      {view.tables.map((t) => (
        <Disclosure
          key={t.title}
          title={t.title}
          hint={`${fmtInt(t.rows.length)} ${t.rows.length === 1 ? "row" : "rows"}`}
          open={expanded}
        >
          <DataTable columns={t.columns} rows={t.rows} />
        </Disclosure>
      ))}
    </div>
  );
}

/**
 * Overview — the landing tab.
 *
 * `views` and `onOpenDomain` are optional: the printed report has no tabs to
 * jump to, so it renders the same page without the domain shortcuts.
 */
function OverviewTab({ summary, views, onOpenDomain, loading }) {
  const m = summary || {};
  return (
    <div className="soc2-tab-body">
      <PendingNote pending={m.pendingCount} what="the totals and scores" />
      <StatRow>
        <StatCard loading={loading} label="Total events" value={fmtInt(m.totalEvents)} sub="all five domains" subColor="muted" />
        <StatCard
          loading={loading}
          label="High severity"
          value={fmtInt(m.highSeverity)}
          sub={Number(m.highSeverity) ? "needs review" : "none recorded"}
          subColor={Number(m.highSeverity) ? "danger" : "success"}
        />
        <StatCard
          loading={loading}
          label="Anomalies"
          value={fmtInt(m.anomalies)}
          sub={`${fmtInt(m.iocMatches)} IOC matches`}
          subColor={Number(m.anomalies) || Number(m.iocMatches) ? "warning" : "success"}
        />
        <StatCard
          loading={loading}
          label="Compliance"
          value={m.complianceScore != null ? `${m.complianceScore}%` : "—"}
          sub={m.complianceScore != null ? "mean of scored domains" : "no events to score"}
          subColor={
            m.complianceScore == null
              ? "muted"
              : m.complianceScore >= 90
                ? "success"
                : m.complianceScore >= 75
                  ? "warning"
                  : "danger"
          }
        />
      </StatRow>

      <div className="soc2-two-col">
        <Section title="Trust service criteria scores">
          {loading ? (
            <SkelLines n={5} />
          ) : (
            <>
              {(m.criteria || []).length > 0 ? (
                <CriteriaScores scores={m.criteria} />
              ) : (
                <div className="evt-empty">No domain recorded any events in this window.</div>
              )}
              {/* an empty domain is an absence of evidence, not a passing control */}
              {(m.silentDomains || []).length > 0 && (
                <div className="soc2-hint soc2-hint-foot">
                  Not scored — no events in this window: {m.silentDomains.join(", ")}.
                </div>
              )}
            </>
          )}
        </Section>
        <Section title={onOpenDomain ? "Domains — open one for the detail" : "Events by domain"}>
          {loading ? (
            <SkelLines n={5} />
          ) : onOpenDomain ? (
            <DomainList views={views} onOpen={onOpenDomain} />
          ) : (
            <BreakdownList items={m.byDomain || []} />
          )}
        </Section>
      </div>

      <Section title="Most recent notable events" wide>
        {loading ? <SkelLines n={6} /> : <EventList events={m.recentEvents || []} maxItems={10} />}
      </Section>
    </div>
  );
}

/**
 * The five domains as shortcuts: event count, state, and a click that opens the
 * domain's own tab. It replaces a plain "events by domain" bar list, which said
 * the same thing without going anywhere.
 */
function DomainList({ views = {}, onOpen }) {
  const domains = TABS.filter((t) => views[t.key]);
  if (domains.length === 0) return <div className="evt-empty">No domain reports yet.</div>;

  return (
    <div className="soc2-domains">
      {domains.map((t) => {
        const v = views[t.key];
        const state = v.pending ? "pending" : v.unavailable ? "error" : "ok";
        return (
          <button
            type="button"
            key={t.key}
            className="soc2-domain"
            onClick={() => onOpen(t.key)}
            title={`Open ${t.label}`}
          >
            <span className="soc2-domain-name">{t.label}</span>
            <span className="soc2-domain-meta">
              {state === "pending" && <Spinner />}
              {state === "error" && <span className="soc2-domain-failed">did not load</span>}
              {state === "ok" && (
                <>
                  <span className="soc2-domain-count">{fmtInt(v.total)} events</span>
                  {v.score != null && (
                    <span className={`soc2-domain-score soc2-domain-score-${scoreTone(v.score)}`}>
                      {v.score}%
                    </span>
                  )}
                </>
              )}
            </span>
            <span className="soc2-domain-go" aria-hidden="true" />
          </button>
        );
      })}
    </div>
  );
}

function scoreTone(score) {
  if (score >= 90) return "good";
  if (score >= 75) return "warn";
  return "bad";
}

function AgentsTab({ agents, loading, onSelect, selectedName }) {
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
        <StatCard loading={loading} label="Pending" value={counts.degraded} sub="watch" subColor="warning" />
        <StatCard loading={loading} label="Offline" value={counts.offline} sub="needs attention" subColor="danger" />
      </StatRow>
      <Section title="Agent inventory" wide>
        {onSelect && (
          <div className="soc2-hint">
            {selectedName
              ? `Reporting on ${selectedName} only — click its row again to include every agent.`
              : "Click an agent to report on that agent only."}
          </div>
        )}
        <AgentsTable
          agents={agents}
          loading={loading}
          onSelect={onSelect}
          selectedName={selectedName}
        />
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
        {(items || []).map((r, i) => (
          <li key={i} className={`soc2-rec soc2-rec-${r.priority || "info"}`}>
            <span className="soc2-rec-num">{String(i + 1).padStart(2, "0")}</span>
            <span className="soc2-rec-text">{r.text}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}
