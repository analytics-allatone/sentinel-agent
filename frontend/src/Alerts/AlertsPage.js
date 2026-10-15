import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import api from "../api/api";
import { once, requestKey } from "../api/inflight";
import AgentPicker from "./AgentPicker";
import {
  CATEGORIES,
  CUSTOM_RANGE,
  DEFAULT_PAGE_SIZE,
  DEFAULT_RANGE,
  PAGE_SIZE_MAX,
  PAGE_SIZE_MIN,
  SEVERITIES,
  SEVERITY_MODES,
  burstSpan,
  count,
  describeWindow,
  digitsOnly,
  alertsToCsv,
  csvFilename,
  filterRows,
  paramsToView,
  viewToParams,
  exactTime,
  groupByRule,
  isoToLocalInput,
  localToIso,
  pageCount,
  rangeProblem,
  rangeWindow,
  readAlerts,
  relativeTime,
  ruleId,
  safePage,
  safePageSize,
  severityOf,
  technique,
  TIME_RANGES,
} from "./alertsFormat";
import "./AlertsPage.css";

/**
 * Detections, from GET /get-alerts.
 *
 * A quarter of a million rows arrive fifty at a time, so the page is built
 * around narrowing rather than around scrolling: severity first, because that
 * is the question anyone opens an alert list with, then the agent and the time
 * window. The counts beside each severity come from the server's own totals for
 * the current filters, so picking one is an informed click rather than a guess.
 *
 * What is true of everything and what is true of this page are kept apart
 * throughout — the figure at the top is the whole result set, the rows are the
 * fifty in hand, and the grouping toggle says plainly that it folds this page.
 */
/** How often a live list re-reads. Long enough not to fight the reader. */
const REFRESH_MS = 30000;

/** Everything numeric is clamped in alertsFormat; this is only the default. */

/** One severity's chip, carrying its own name as well as its colour. */
function SeverityChip({ alert }) {
  const { label, tone } = severityOf(alert);
  return <span className={`al-sev al-sev--${tone}`}>{label}</span>;
}

/**
 * What kind of thing the rule watched: a file, a process, the network.
 *
 * Blank on older records — the field was only filled in later — and an empty
 * chip would read as a category called "nothing".
 */
function Category({ value }) {
  const name = String(value || "").trim();
  if (!name) return null;
  return <span className={`al-category al-category--${name}`}>{name}</span>;
}

/** A technique, linked to the ATT&CK page that explains it. */
function Technique({ value }) {
  const found = technique(value);
  if (!found) return null;
  return (
    <a
      className="al-technique"
      href={found.url}
      target="_blank"
      rel="noreferrer noopener"
      title={`MITRE ATT&CK ${found.id}`}
    >
      {found.id}
    </a>
  );
}

/** One detection. */
function AlertRow({ alert, now }) {
  return (
    <li className="al-row">
      <SeverityChip alert={alert} />

      <div className="al-row-main">
        <h3 className="al-detail">{alert.detail || "Unnamed detection"}</h3>

        <div className="al-row-meta">
          <Category value={alert.category} />

          <Technique value={alert.technique} />

          <span className="al-meta">
            <span className="al-meta-key">agent</span>
            {alert.agent_name || "—"}
          </span>

          <span className="al-meta">
            <span className="al-meta-key">on</span>
            <span className="al-mono">{alert.entity || "—"}</span>
          </span>

          <span className="al-meta al-meta--soft" title={ruleId(alert.rule_id)}>
            {ruleId(alert.rule_id).slice(0, 8)}
          </span>
        </div>
      </div>

      <div className="al-row-figures">
        {/* An alert is a run of events, so both the count and the window it
            covers: nine at once is not nine over an hour. */}
        <span className="al-events">
          {count(alert.event_count)} event{Number(alert.event_count) === 1 ? "" : "s"}
        </span>
        <span className="al-span">{burstSpan(alert)}</span>
      </div>

      <time className="al-when" dateTime={alert.last_seen} title={exactTime(alert.last_seen)}>
        {relativeTime(alert.last_seen, now)}
      </time>
    </li>
  );
}

/** The same rule many times over, folded into one row. */
function GroupRow({ group, now }) {
  return (
    <li className="al-row al-row--group">
      <SeverityChip alert={group} />

      <div className="al-row-main">
        <h3 className="al-detail">
          {group.detail || "Unnamed detection"}
          <span className="al-group-count">×{group.alerts}</span>
        </h3>

        <div className="al-row-meta">
          <Category value={group.category} />

          <Technique value={group.technique} />

          <span className="al-meta">
            <span className="al-meta-key">
              {group.agents.length === 1 ? "agent" : "agents"}
            </span>
            {group.agents.slice(0, 3).join(", ")}
            {group.agents.length > 3 && ` +${group.agents.length - 3}`}
          </span>

          <span className="al-meta">
            <span className="al-meta-key">on</span>
            <span className="al-mono">
              {group.entities.slice(0, 2).join(", ")}
              {group.entities.length > 2 && ` +${group.entities.length - 2}`}
            </span>
          </span>
        </div>
      </div>

      <div className="al-row-figures">
        <span className="al-events">{count(group.events)} events</span>
        <span className="al-span">{burstSpan(group)}</span>
      </div>

      <time className="al-when" dateTime={group.last_seen} title={exactTime(group.last_seen)}>
        {relativeTime(group.last_seen, now)}
      </time>
    </li>
  );
}

export default function AlertsPage() {
  const [search, setSearch] = useSearchParams();
  // Read once, at mount: after that the page owns the view and writes it back.
  const opening = useRef(paramsToView(search)).current;

  const [severity, setSeverity] = useState(opening.severity); // 0 = every severity
  // Which question the chosen level asks: severity_min, or severity exactly.
  const [severityMode, setSeverityMode] = useState(opening.severityMode);
  const [grouped, setGrouped] = useState(false);
  const [rowFilter, setRowFilter] = useState("");
  const [live, setLive] = useState(false);
  const [page, setPage] = useState(opening.page);
  const [pageDraft, setPageDraft] = useState(String(opening.page));

  /**
   * What the fields hold, which is not yet what has been asked for.
   *
   * Every input on the row is a draft: typing an agent, picking a window,
   * changing the page size. One Apply commits the lot and one request follows,
   * rather than a fetch per control — at a quarter of a million rows, three
   * half-finished queries on the way to the one that was meant is a lot of
   * waiting for nothing.
   */
  const [draft, setDraft] = useState({
    agent: opening.applied.agent,
    category: opening.applied.category,
    range: opening.applied.range,
    from: opening.applied.customWindow
      ? isoToLocalInput(opening.applied.customWindow.from_dt)
      : "",
    to: opening.applied.customWindow ? isoToLocalInput(opening.applied.customWindow.to_dt) : "",
    size: String(opening.applied.pageSize),
  });

  /** What the last Apply committed. Every request is drawn from this. */
  const [applied, setApplied] = useState(opening.applied);

  const [rangeError, setRangeError] = useState("");

  const [status, setStatus] = useState("loading"); // loading | ready | error
  const [error, setError] = useState("");
  const [result, setResult] = useState({ total: 0, page: 1, pageSize: 0, alerts: [] });
  const [tallies, setTallies] = useState(null);
  const [now, setNow] = useState(() => Date.now());

  const setField = (name, value) => setDraft((d) => ({ ...d, [name]: value }));

  /**
   * Every request is bounded at both ends: a quarter of a million rows with no
   * window is not a view, and the endpoint pages through them either way.
   *
   * A preset is recomputed whenever the filters are committed, so "last hour"
   * keeps meaning the last hour; a custom window holds the two instants given.
   */
  const window_ = useMemo(() => {
    if (applied.range === CUSTOM_RANGE) return applied.customWindow;
    return rangeWindow(applied.range);
  }, [applied]);

  const baseParams = useMemo(() => {
    const params = {};
    if (applied.agent.trim()) params.agent_name = applied.agent.trim();
    if (applied.category) params.category = applied.category;
    if (window_) {
      params.from_dt = window_.from_dt;
      params.to_dt = window_.to_dt;
    }
    return params;
  }, [applied, window_]);

  const load = useCallback(async () => {
    setStatus("loading");
    setError("");

    try {
      const params = {
        ...baseParams,
        // One level, two possible questions — and only one of the two
        // parameters is ever sent.
        ...(severity
          ? { [severityMode === "exact" ? "severity" : "severity_min"]: severity }
          : {}),
        // Numbers, never the strings the fields hold them as.
        page: Number(page),
        page_size: Number(applied.pageSize),
      };

      // Two identical requests in the same moment are one question. React
      // alone produces them: an effect re-run under StrictMode, a filter
      // changed twice before the first answer lands.
      const res = await once(requestKey("/get-alerts", params), () =>
        api.get("/get-alerts", { params, skipGlobalLoader: true })
      );
      setResult(readAlerts(res.data));
      setNow(Date.now());
      setStatus("ready");
    } catch (err) {
      const code = err.response && err.response.status;
      const detail = err.response && err.response.data && err.response.data.detail;
      // A request carrying a category is the one most likely to have been
      // refused by the server, so the reader is told which filter to drop
      // rather than being asked to try the same thing again.
      //
      // The status is often missing rather than 500: an unhandled server error
      // skips the CORS middleware, the browser blocks the response, and axios
      // is left with no `response` at all. Both shapes are covered.
      if (applied.category && (code === 500 || code === undefined)) {
        setError(
          `The server could not answer with the category "${applied.category}". ` +
            "Clearing the category should bring the alerts back; the other filters are unaffected."
        );
      } else {
        setError(
          typeof detail === "string" ? detail : "Could not read the alerts. Please try again."
        );
      }
      setStatus("error");
    }
  }, [baseParams, severity, severityMode, page, applied.pageSize]);

  useEffect(() => {
    load();
  }, [load]);

  /**
   * Re-read on a timer, while that still means anything.
   *
   * Alerts arrive constantly — tens of thousands a day — so a list left open is
   * stale within a minute. But refreshing underneath someone who is reading is
   * worse than stale: only page one refreshes, because every other page would
   * shift as new alerts push rows down it, and a row filter in progress pauses
   * it, because replacing the rows being searched loses the search.
   */
  const refreshing = live && page === 1 && !rowFilter.trim();

  useEffect(() => {
    if (!refreshing) return undefined;
    const timer = setInterval(() => load(), REFRESH_MS);
    return () => clearInterval(timer);
  }, [refreshing, load]);

  /**
   * Keep the address bar showing what is on screen.
   *
   * Replaced rather than pushed: a filter page where every tweak and every one
   * of five thousand pages lands in history makes the back button useless for
   * leaving the page at all. The link stays shareable and a refresh stays put,
   * which is what the address bar is for here.
   */
  useEffect(() => {
    const params = viewToParams({ severity, severityMode, applied });
    if (page > 1) params.page = String(page);
    setSearch(params, { replace: true });
  }, [severity, severityMode, applied, page, setSearch]);

  /**
   * How many alerts sit at each severity, across everything the other filters
   * match — not across the page.
   *
   * One request per level, each asking for a single row: all that is wanted is
   * the `total` the server reports alongside it. They are deliberately not
   * blocking, so the list is readable before the counts land.
   */
  const tallyRun = useRef(0);
  useEffect(() => {
    const run = ++tallyRun.current;
    setTallies(null);

    Promise.all(
      SEVERITIES.map((s) => {
        const params = { ...baseParams, severity: s.level, page: 1, page_size: 1 };
        return once(requestKey("/get-alerts", params), () =>
          api.get("/get-alerts", { params, skipGlobalLoader: true })
        )
          .then((res) => [s.level, readAlerts(res.data).total])
          .catch(() => [s.level, null]);
      })
    ).then((pairs) => {
      // a filter changed while these were in flight: that answer is stale
      if (run !== tallyRun.current) return;
      setTallies(Object.fromEntries(pairs));
    });
  }, [baseParams]);

  const pages = pageCount(result.total, applied.pageSize);

  // Narrowed before folding, so a folded row counts only what is on screen.
  const shown = useMemo(() => filterRows(result.alerts, rowFilter), [result.alerts, rowFilter]);
  const groups = useMemo(() => groupByRule(shown), [shown]);
  /**
   * The levels added up — or nothing, when none of them could be counted.
   *
   * Summing a set of failed counts as zero would put a confident "0" beside
   * "Any" while every level beside it says it does not know.
   */
  const tallyTotal = useMemo(() => {
    if (!tallies) return null;
    const known = Object.values(tallies).filter((n) => n != null);
    if (known.length === 0) return null;
    return known.reduce((sum, n) => sum + (Number(n) || 0), 0);
  }, [tallies]);

  const firstShown = result.total === 0 ? 0 : (page - 1) * applied.pageSize + 1;
  const lastShown = (page - 1) * applied.pageSize + result.alerts.length;

  /** Move to a page, keeping the box and the request agreeing. */
  const goToPage = (next) => {
    const safe = safePage(next, pages);
    setPageDraft(String(safe));
    setPage(safe);
  };

  /**
   * The rows on screen, as a file.
   *
   * These rows and no others: one page out of a result that runs to tens of
   * thousands, narrowed further by whatever the row filter left. The button
   * carries the count for that reason — a file called "alerts" holding fifty
   * of them is the kind of thing that gets pasted into a report as though it
   * were the whole picture.
   */
  const exportCsv = () => {
    // the BOM is what makes Excel read the file as UTF-8 rather than as the
    // local codepage, which otherwise mangles every non-ASCII hostname
    const blob = new Blob(["﻿" + alertsToCsv(shown)], {
      type: "text/csv;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = csvFilename();
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  /** A different question is a different first page. */
  const chooseSeverity = (level) => {
    setSeverity(level);
    setPage(1);
    setPageDraft("1");
  };

  const chooseMode = (id) => {
    setSeverityMode(id);
    setPage(1);
    setPageDraft("1");
  };

  /**
   * The one Apply. It commits every field on the row and the request follows.
   *
   * A hand-typed window is checked here rather than sent: the endpoint answers
   * a backwards range with an empty list, which reads as "no alerts" when it
   * means "those two dates are the wrong way round".
   */
  const apply = (e) => {
    e.preventDefault();

    let customWindow = applied.customWindow;
    if (draft.range === CUSTOM_RANGE) {
      const problem = rangeProblem(draft.from, draft.to);
      setRangeError(problem);
      if (problem) return;
      customWindow = { from_dt: localToIso(draft.from), to_dt: localToIso(draft.to) };
    } else {
      setRangeError("");
    }

    // what the endpoint will accept, shown back in the field it came from
    const size = safePageSize(draft.size);
    setField("size", String(size));

    setPage(1);
    setPageDraft("1");
    setApplied({
      agent: draft.agent,
      category: draft.category,
      range: draft.range,
      customWindow,
      pageSize: size,
    });
  };

  /** Back to the window and the filters the page opens with. */
  const clearFilters = () => {
    setSeverity(0);
    setSeverityMode("min");
    setRangeError("");
    setDraft({
      agent: "",
      category: "",
      range: DEFAULT_RANGE,
      from: "",
      to: "",
      size: String(DEFAULT_PAGE_SIZE),
    });
    setPage(1);
    setPageDraft("1");
    setApplied({
      agent: "",
      category: "",
      range: DEFAULT_RANGE,
      customWindow: null,
      pageSize: DEFAULT_PAGE_SIZE,
    });
  };

  return (
    <div className="al-page">
      <header className="al-head">
        <div className="al-head-main">
          <h1 className="al-title">Alerts</h1>
          <p className="al-lead">
            Detections raised by the Sigma rules the agents run. Newest first.
          </p>
        </div>

        <div className="al-head-figure">
          <strong className="al-hero">{count(result.total)}</strong>
          <span className="al-hero-label">
            {describeWindow(window_) || "matching these filters"}
          </span>
        </div>
      </header>

      {/* ── what to look at ─────────────────────────────────────── */}
      <section className="al-filters" aria-label="Filters">
        <div className="al-filter">
          <div className="al-sev-head">
            <span className="al-filter-label" id="al-sev-label">
              Severity
            </span>

            {/* Which of the two parameters a chosen level sends. */}
            <div className="al-mode" role="group" aria-label="How the level is matched">
              {SEVERITY_MODES.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  className={`al-mode-btn ${severityMode === m.id ? "is-on" : ""}`}
                  aria-pressed={severityMode === m.id}
                  onClick={() => chooseMode(m.id)}
                  title={`sends ${m.param}`}
                >
                  {m.label}
                </button>
              ))}
            </div>
          </div>

          <div className="al-seg" role="group" aria-labelledby="al-sev-label">
            <button
              type="button"
              className={`al-seg-btn ${severity === 0 ? "is-on" : ""}`}
              aria-pressed={severity === 0}
              onClick={() => chooseSeverity(0)}
            >
              Any
              <span className="al-seg-count">
                {!tallies ? "…" : tallyTotal == null ? "—" : count(tallyTotal)}
              </span>
            </button>

            {SEVERITIES.map((s) => (
              <button
                key={s.level}
                type="button"
                className={`al-seg-btn al-seg-btn--${s.tone} ${
                  severity === s.level ? "is-on" : ""
                }`}
                aria-pressed={severity === s.level}
                onClick={() => chooseSeverity(s.level)}
                title={severityMode === "exact" ? s.label : `${s.label} and above`}
              >
                {s.label}
                <span className="al-seg-count">
                  {tallies ? (tallies[s.level] == null ? "—" : count(tallies[s.level])) : "…"}
                </span>
              </button>
            ))}
          </div>

          <p className="al-filter-hint">
            {severityMode === "exact" ? (
              <>
                A level selects <em>that level only</em>, so each count beside a level is
                exactly what picking it will show.
              </>
            ) : (
              <>
                A level selects it <em>and everything above it</em>; the counts are for that
                level alone, across every alert the other filters match.
              </>
            )}
          </p>
        </div>

        {/* One row, one Apply: nothing here reaches the API until it is pressed. */}
        <form className="al-filter-row" onSubmit={apply}>
          <div className="al-filter">
            <label className="al-filter-label" htmlFor="al-agent">
              Agent
            </label>
            <AgentPicker value={draft.agent} onChange={(name) => setField("agent", name)} />
          </div>

          <div className="al-filter">
            <label className="al-filter-label" htmlFor="al-category">
              Category
            </label>
            <select
              id="al-category"
              className="al-input al-select"
              value={draft.category}
              onChange={(e) => setField("category", e.target.value)}
            >
              <option value="">Every category</option>
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>

          <div className="al-filter">
            <label className="al-filter-label" htmlFor="al-range">
              Seen
            </label>
            <select
              id="al-range"
              className="al-input al-select al-select--range"
              value={draft.range}
              onChange={(e) => {
                const next = e.target.value;
                setRangeError("");

                if (next === CUSTOM_RANGE) {
                  // Seeded from the window on screen, so "custom" starts from
                  // what is being looked at rather than from two blank fields.
                  const seed = window_ || rangeWindow(DEFAULT_RANGE);
                  setDraft((d) => ({
                    ...d,
                    range: next,
                    from: isoToLocalInput(seed.from_dt),
                    to: isoToLocalInput(seed.to_dt),
                  }));
                  return;
                }

                setField("range", next);
              }}
            >
              {TIME_RANGES.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.label}
                </option>
              ))}
              <option value={CUSTOM_RANGE}>Custom range…</option>
            </select>
          </div>

          {draft.range === CUSTOM_RANGE && (
            <>
              <div className="al-filter">
                <label className="al-filter-label" htmlFor="al-from">
                  From
                </label>
                <input
                  id="al-from"
                  className="al-input"
                  type="datetime-local"
                  value={draft.from}
                  onChange={(e) => setField("from", e.target.value)}
                />
              </div>

              <div className="al-filter">
                <label className="al-filter-label" htmlFor="al-to">
                  To
                </label>
                <input
                  id="al-to"
                  className="al-input"
                  type="datetime-local"
                  value={draft.to}
                  onChange={(e) => setField("to", e.target.value)}
                />
              </div>
            </>
          )}

          <div className="al-filter">
            <label className="al-filter-label" htmlFor="al-size">
              Per page
            </label>
            <div className="al-num-field">
              <input
                id="al-size"
                className="al-input al-num"
                type="text"
                inputMode="numeric"
                autoComplete="off"
                value={draft.size}
                aria-describedby="al-size-hint"
                /* Only digits ever reach the field, so only a number can ever
                   leave it; "" stays legal while someone is still typing. */
                onChange={(e) => setField("size", digitsOnly(e.target.value))}
              />
              <span className="al-num-hint" id="al-size-hint">
                {PAGE_SIZE_MIN}–{PAGE_SIZE_MAX}
              </span>
            </div>
          </div>

          <button type="submit" className="phi-btn phi-btn--sm al-apply">
            Apply
          </button>

          {rangeError && (
            <p className="al-range-error" role="alert">
              {rangeError}
            </p>
          )}
        </form>
      </section>

      {/* ── the rows ────────────────────────────────────────────── */}
      <section className="al-results" aria-label="Alerts">
        <div className="al-results-head">
          <p className="al-showing">
            {status !== "ready"
              ? " "
              : result.alerts.length === 0
                ? "Nothing matched"
                : rowFilter.trim()
                  ? // what the box narrowed, and what it did not touch
                    `${count(shown.length)} of these ${count(result.alerts.length)} rows · ${count(
                      result.total
                    )} in the whole result`
                  : `Showing ${count(firstShown)}–${count(lastShown)} of ${count(result.total)}`}
          </p>

          <div className="al-results-tools">
            <input
              type="search"
              className="al-input al-row-filter"
              placeholder="Filter these rows…"
              aria-label="Filter the rows on this page"
              value={rowFilter}
              onChange={(e) => setRowFilter(e.target.value)}
            />

            <label className="al-group-toggle">
              <input
                type="checkbox"
                checked={live}
                onChange={(e) => setLive(e.target.checked)}
              />
              {/* the dot is lit only while it is really refreshing, which is
                  not the same as the box being ticked */}
              <span className="al-live">
                <span
                  className={`al-live-dot ${refreshing ? "is-on" : ""}`}
                  aria-hidden="true"
                />
                Live
              </span>
            </label>

            <button
              type="button"
              className="phi-btn phi-btn--sm phi-btn--secondary"
              onClick={exportCsv}
              disabled={shown.length === 0}
            >
              Export {count(shown.length)} rows
            </button>

            <label className="al-group-toggle">
              <input
                type="checkbox"
                checked={grouped}
                onChange={(e) => setGrouped(e.target.checked)}
              />
              {/* said plainly: folding cannot reach past the rows in hand */}
              <span>Fold repeats on this page</span>
            </label>
          </div>
        </div>

        {status === "loading" && (
          <ul className="al-list" aria-busy="true">
            {Array.from({ length: 6 }).map((_, i) => (
              <li className="al-row al-row--skeleton" key={i}>
                <span className="phi-skeleton" />
              </li>
            ))}
          </ul>
        )}

        {status === "error" && (
          <div className="al-empty al-empty--error" role="alert">
            <p>{error}</p>
            <button type="button" className="phi-btn phi-btn--sm" onClick={load}>
              Try again
            </button>
          </div>
        )}

        {status === "ready" && result.alerts.length === 0 && (
          <div className="al-empty">
            <p>No alert matches these filters.</p>
            {(severity ||
              applied.agent ||
              applied.range !== DEFAULT_RANGE ||
              applied.pageSize !== DEFAULT_PAGE_SIZE) && (
              <button
                type="button"
                className="phi-btn phi-btn--sm phi-btn--secondary"
                onClick={clearFilters}
              >
                Clear the filters
              </button>
            )}
          </div>
        )}

        {status === "ready" && result.alerts.length > 0 && shown.length === 0 && (
          <div className="al-empty">
            <p>No row on this page matches that.</p>
            {/* the box reaches the fifty rows in hand and no further */}
            <p className="al-empty-note">
              It searches the {count(result.alerts.length)} rows already fetched. To search the
              other {count(Math.max(0, result.total - result.alerts.length))}, use the filters
              above.
            </p>
            <button
              type="button"
              className="phi-btn phi-btn--sm phi-btn--secondary"
              onClick={() => setRowFilter("")}
            >
              Clear this filter
            </button>
          </div>
        )}

        {status === "ready" && shown.length > 0 && (
          <ul className="al-list">
            {grouped
              ? groups.map((group) => <GroupRow key={group.key} group={group} now={now} />)
              : shown.map((alert) => <AlertRow key={alert.id} alert={alert} now={now} />)}
          </ul>
        )}

        {pages > 1 && (
          <nav className="al-pager" aria-label="Pages">
            <button
              type="button"
              className="phi-btn phi-btn--sm phi-btn--secondary"
              disabled={page <= 1 || status === "loading"}
              onClick={() => goToPage(page - 1)}
            >
              ← Newer
            </button>

            {/* The page number is a field, not a label: at five thousand pages
                the only way to reach one is to say which. */}
            <form
              className="al-pager-jump"
              onSubmit={(e) => {
                e.preventDefault();
                goToPage(pageDraft);
              }}
            >
              <label className="al-pager-label" htmlFor="al-page">
                Page
              </label>

              <input
                id="al-page"
                className="al-input al-num"
                type="text"
                inputMode="numeric"
                autoComplete="off"
                value={pageDraft}
                onChange={(e) => setPageDraft(digitsOnly(e.target.value))}
                onBlur={() => goToPage(pageDraft)}
              />

              <span className="al-pager-label">of {count(pages)}</span>
            </form>

            <button
              type="button"
              className="phi-btn phi-btn--sm phi-btn--secondary"
              disabled={page >= pages || status === "loading"}
              onClick={() => goToPage(page + 1)}
            >
              Older →
            </button>
          </nav>
        )}
      </section>
    </div>
  );
}
