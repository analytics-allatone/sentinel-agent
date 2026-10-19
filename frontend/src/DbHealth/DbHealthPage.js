import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import api from "../api/api";
import {
  blockedSessions,
  columnsOf,
  groupChecks,
  formatBytes,
  formatDuration,
  formatTimestamp,
  formatValue,
  healthTone,
  hitRatios,
  inspectionNotice,
  isRowArray,
  memoryBreakdown,
  partitionFields,
  pickStats,
  resourceLimits,
  splitRecord,
  tablespaces,
  titleOf,
  unusableIndexes,
  unwrapRows,
} from "./dbHealthFormat";
import { DayColumns, RankedBars } from "./DbHealthCharts";
import {
  archiveSeries,
  expiringAccounts,
  topSegments,
  topSqlByRuns,
  topSqlByTime,
} from "./chartData";
import "./DbHealthPage.css";

/**
 * The stored health record for one database, from GET /api/db/data.
 *
 * Which database is fixed by the URL — `?agent=…&engine=…&service=…`, as the
 * services panel hands it over. The only two query options the endpoint offers
 * are editable here: `limit` (1..500) and `compact` (drop null columns).
 *
 * The record is a set of named checks whose contents differ per engine, so the
 * page renders by shape rather than by a fixed list: a list of objects becomes a
 * table, an object becomes a field list, a scalar becomes a value. Nothing is
 * dropped for being unrecognised.
 */
const LIMIT_MIN = 1;
const LIMIT_MAX = 500;
const DEFAULT_LIMIT = 1;

/**
 * Checks that are drawn as a reading of their own further up the page.
 *
 * Skipped by the generic renderer only when that reading actually appeared: a
 * check that was run and came back empty still has something to say, and
 * "Locks blocking — nothing reported" is the page saying it. Dropping the card
 * as well as the alarm would turn "nobody is waiting" into silence.
 */
function ownSection({ ratios, spaces, blocked, limits, memory }) {
  const drawn = [];
  if (ratios.length) drawn.push("cache_hit_ratio");
  if (spaces.length) drawn.push("database_sizes");
  if (blocked.length) drawn.push("locks_blocking");
  if (limits.length) drawn.push("resource_limits");
  if (memory) drawn.push("memory");
  return drawn;
}

/** Checks worth showing first — the rest keep the order the API sent. */
const LEAD_CHECKS = [
  "health_summary",
  "basic_connectivity",
  "database_size",
  "active_connections",
  "cache_hit_ratio",
];

function Stat({ label, value, sub, tone }) {
  return (
    <div className={`dbh-stat ${tone ? `dbh-stat--${tone}` : ""}`}>
      <span className="dbh-stat-label">{label}</span>
      <strong className="dbh-stat-value">{value}</strong>
      {sub && <span className="dbh-stat-sub">{sub}</span>}
    </div>
  );
}

/**
 * How many rows of a check are worth showing before the reader asks for more.
 *
 * `sessions_by_user` arrives 50 rows long and `top_segments` 20; printed in
 * full they push everything else off the page, and the tail of a list that is
 * already sorted by size is the part nobody came for.
 */
const ROW_PREVIEW = 8;

/** A list of objects, as a table — long ones folded until asked. */
function RowTable({ rows }) {
  const [expanded, setExpanded] = useState(false);
  const columns = columnsOf(rows);
  const folded = rows.length > ROW_PREVIEW && !expanded;
  const visible = folded ? rows.slice(0, ROW_PREVIEW) : rows;

  return (
    <>
      <div className="dbh-table-wrap">
        <table className="dbh-table">
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c}>{titleOf(c)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((row, i) => (
              <tr key={i}>
                {columns.map((c) => {
                  const raw = row[c];
                  // SQL text runs to 400 characters; it is clamped to a few
                  // lines rather than allowed to set the row height.
                  const long = typeof raw === "string" && raw.length > 90;
                  return (
                    <td key={c} className={long ? "dbh-cell--long" : ""} title={String(raw ?? "")}>
                      {formatValue(c, raw)}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {rows.length > ROW_PREVIEW && (
        <button
          type="button"
          className="dbh-more phi-btn phi-btn--sm phi-btn--secondary"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
        >
          {expanded
            ? `Show fewer`
            : `Show all ${rows.length} rows`}
        </button>
      )}
    </>
  );
}

/** Scalars as label/value pairs. */
function FieldList({ entries }) {
  if (entries.length === 0) return null;
  return (
    <dl className="dbh-fields">
      {entries.map(([key, value]) => (
        <div className="dbh-field" key={key}>
          <dt>{titleOf(key)}</dt>
          <dd title={String(value ?? "")}>{formatValue(key, value)}</dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * The record's own fields, as a table.
 *
 * A row that carries nothing is marked rather than dropped: "this was not
 * measured" is an answer, and one the reader should be able to see at a glance
 * without comparing against a list of what the engine could have sent.
 */
function RecordTable({ entries }) {
  if (entries.length === 0) {
    return <p className="dbh-empty">No field matches that filter.</p>;
  }

  return (
    <div className="dbh-kv-wrap">
      <table className="dbh-table dbh-kv">
        <thead>
          <tr>
            <th>Field</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {entries.map(([key, value]) => {
            const empty = value === null || value === undefined || value === "";
            return (
              <tr key={key} className={empty ? "dbh-kv-row--empty" : ""}>
                <td className="dbh-kv-key">{titleOf(key)}</td>
                <td className="dbh-kv-value" title={String(value ?? "")}>
                  {formatValue(key, value)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/**
 * The four checks whose shape says more than their rows do.
 *
 * Each builds from the whole record rather than from the list alone, so a chart
 * can reach for a second field — the day name beside the date, the executions
 * beside the elapsed time — without the card having to pass it in.
 */
const CHARTS = {
  top_sql_elapsed: (record) => (
    <RankedBars
      items={topSqlByTime(record)}
      caption="Where the database spent its time. Hover a row for the statement."
    />
  ),
  top_sql_executions: (record) => (
    <RankedBars
      items={topSqlByRuns(record)}
      caption="Run most often — cheap individually, and the reason the cache matters."
    />
  ),
  top_segments: (record) => (
    <RankedBars items={topSegments(record)} caption="The objects holding the bytes." />
  ),
  archive_log_daily: (record) => (
    <DayColumns
      points={archiveSeries(record)}
      caption="Redo written per day, in date order — only the days that archived anything."
    />
  ),
};

function chartFor(name, record) {
  const build = CHARTS[name];
  return build ? build(record) : null;
}

/** One check: its scalars first, then each nested list as its own table. */
function CheckCard({ name, value, chart }) {
  if (isRowArray(value)) {
    return (
      <section className="dbh-card">
        <h3 className="dbh-card-title">
          {titleOf(name)}
          <span className="dbh-card-count">{value.length}</span>
        </h3>

        {/* The picture is the summary and the table underneath it is the
            detail — the same list once, not twice in two places. */}
        {chart}

        <RowTable rows={value} />
      </section>
    );
  }

  if (Array.isArray(value)) {
    return (
      <section className="dbh-card">
        <h3 className="dbh-card-title">{titleOf(name)}</h3>
        {value.length === 0 ? (
          <p className="dbh-empty">Nothing reported.</p>
        ) : (
          <p className="dbh-inline-list">{value.map(String).join(", ")}</p>
        )}
      </section>
    );
  }

  const entries = Object.entries(value || {});
  const scalars = entries.filter(([, v]) => v === null || typeof v !== "object");
  const nested = entries.filter(([, v]) => v !== null && typeof v === "object");

  return (
    <section className="dbh-card">
      <h3 className="dbh-card-title">{titleOf(name)}</h3>

      {entries.length === 0 && <p className="dbh-empty">Nothing reported.</p>}

      <FieldList entries={scalars} />

      {nested.map(([key, nestedValue]) => (
        <div className="dbh-subsection" key={key}>
          <h4 className="dbh-sub-title">
            {titleOf(key)}
            {Array.isArray(nestedValue) && (
              <span className="dbh-card-count">{nestedValue.length}</span>
            )}
          </h4>
          {isRowArray(nestedValue) ? (
            <RowTable rows={nestedValue} />
          ) : Array.isArray(nestedValue) ? (
            <p className="dbh-empty">Nothing reported.</p>
          ) : (
            <FieldList entries={Object.entries(nestedValue)} />
          )}
        </div>
      ))}
    </section>
  );
}

/* ───────────────────────────────────────────────────────────────
   Measured figures: a ratio against a limit is a meter, not a table
   ─────────────────────────────────────────────────────────────── */

/** The state in words. Colour alone is not a reading. */
const RATIO_WORD = { ok: "healthy", warn: "low", bad: "very low", muted: "unknown" };
const USAGE_WORD = { ok: "ok", warn: "filling up", bad: "nearly full", muted: "unknown" };

/** Megabytes as the size they are — `max_mb` runs to eight figures. */
function formatMb(mb) {
  const n = Number(mb);
  if (!Number.isFinite(n)) return "—";
  return formatBytes(n * 1024 * 1024);
}

/**
 * One ratio against its limit.
 *
 * The track is a pale step of the same ramp as the fill, so a near-empty bar
 * still reads as a bar; the fill carries the severity. The percentage and the
 * state are both written out, because a reader who cannot separate the hues
 * still has to be able to read the number.
 */
function Meter({ label, value, hint, level, word = RATIO_WORD }) {
  const pct = Math.max(0, Math.min(100, Number(value) || 0));
  return (
    <div className="dbh-meter">
      <div className="dbh-meter-head">
        <span className="dbh-meter-label">{label}</span>
        <strong className="dbh-meter-value">{value}%</strong>
      </div>

      <div
        className="dbh-meter-track"
        role="img"
        aria-label={`${label}: ${value} percent, ${word[level] || level}`}
      >
        <span className={`dbh-meter-fill dbh-meter-fill--${level}`} style={{ width: `${pct}%` }} />
      </div>

      <div className="dbh-meter-foot">
        <span className={`dbh-level dbh-level--${level}`}>{word[level] || level}</span>
        {hint && <span className="dbh-meter-hint">{hint}</span>}
      </div>
    </div>
  );
}

/**
 * Sessions that are waiting on another session.
 *
 * Put above the figures because it is the only thing on this page that is
 * somebody stuck right now, rather than a measurement of how things have been.
 */
function BlockedList({ rows }) {
  return (
    <ul className="dbh-block-list">
      {rows.map((row, i) => (
        <li className="dbh-block" key={`${row.blocked}-${i}`}>
          <span className={`dbh-level dbh-level--${row.level}`}>
            {formatDuration(row.seconds)}
          </span>

          <div className="dbh-block-body">
            <p className="dbh-block-who">
              <span className="dbh-mono">SID {row.blocked}</span>
              {row.username && <span className="dbh-block-user">{row.username}</span>}
              <span className="dbh-block-arrow" aria-label="is blocked by">
                ← blocked by
              </span>
              <span className="dbh-mono">SID {row.blocker}</span>
            </p>

            {row.event && (
              <p className="dbh-block-event">
                {row.event}
                {row.waitClass && <span className="dbh-block-class">{row.waitClass}</span>}
              </p>
            )}
          </div>
        </li>
      ))}
    </ul>
  );
}

/**
 * How close each resource is to its configured limit.
 *
 * The bar is where it is now; the notch is the highest it has ever reached. An
 * instance at 30% that peaked at 95% is one busy afternoon from refusing
 * connections, and the notch is the only thing on the page that says so.
 */
function LimitList({ rows }) {
  return (
    <ul className="dbh-limit-list">
      {rows.map((row) => (
        <li className="dbh-limit" key={row.name}>
          <div className="dbh-limit-head">
            <span className="dbh-limit-name">{titleOf(row.name)}</span>
            <span className="dbh-limit-figure">
              {row.current.toLocaleString()} <span className="dbh-ts-of">of</span>{" "}
              {row.limit.toLocaleString()}
            </span>
          </div>

          <div
            className="dbh-limit-track"
            role="img"
            aria-label={`${row.name}: ${row.current} of ${row.limit} in use, peak ${row.peak}`}
          >
            <span
              className={`dbh-limit-fill dbh-limit-fill--${row.level}`}
              style={{ width: `${Math.max(0, Math.min(100, row.pct || 0))}%` }}
            />
            {row.peakPct != null && (
              <span
                className="dbh-limit-peak"
                style={{ left: `${Math.max(0, Math.min(100, row.peakPct))}%` }}
                title={`peak ${row.peak.toLocaleString()}`}
              />
            )}
          </div>

          <div className="dbh-limit-foot">
            <span className={`dbh-level dbh-level--${row.level}`}>
              {row.pct == null ? "unknown" : `${Math.round(row.pct)}% in use`}
            </span>
            {row.peakPct != null && (
              <span className="dbh-ts-note">
                peak {row.peak.toLocaleString()} — {Math.round(row.peakPct)}% of the limit
              </span>
            )}
          </div>
        </li>
      ))}
    </ul>
  );
}

/** The instance's memory, as a whole and its parts. */
function MemoryPanel({ memory }) {
  return (
    <>
      <div className="dbh-mem-totals">
        {memory.sga != null && (
          <div className="dbh-mem-total">
            <span className="dbh-stat-label">SGA</span>
            <strong className="dbh-stat-value">{formatBytes(memory.sga)}</strong>
          </div>
        )}
        {memory.pgaAllocated != null && (
          <div className="dbh-mem-total">
            <span className="dbh-stat-label">PGA allocated</span>
            <strong className="dbh-stat-value">{formatBytes(memory.pgaAllocated)}</strong>
          </div>
        )}
      </div>

      <ul className="dbh-ts-list">
        {memory.parts.map((part) => (
          <li className="dbh-ts" key={part.label}>
            <div className="dbh-ts-head">
              <span className="dbh-ts-name">{part.label}</span>
              <span className="dbh-ts-figure">
                {formatBytes(part.bytes)} <span className="dbh-ts-of">of</span>{" "}
                {formatBytes(part.of)}
              </span>
            </div>

            <div
              className="dbh-ts-track"
              role="img"
              aria-label={`${part.label}: ${Math.round(part.pct)} percent`}
            >
              <span
                className="dbh-ts-fill dbh-ts-fill--neutral"
                style={{ width: `${Math.max(0, Math.min(100, part.pct))}%` }}
              />
            </div>

            <div className="dbh-ts-foot">
              <span className="dbh-ts-note">
                {Math.round(part.pct)}% of {part.ofLabel}
              </span>
            </div>
          </li>
        ))}
      </ul>
    </>
  );
}

/**
 * Tablespace pressure.
 *
 * The bar is how full the space is *today*; the colour is whether that matters.
 * Those are different questions on Oracle, where a datafile at 99% of 300 MB
 * with 32 TB of autoextend left is simply a datafile doing its job. Both
 * numbers are spelled out under the bar so the colour is never a mystery.
 */
function TablespaceList({ items }) {
  return (
    <ul className="dbh-ts-list">
      {items.map((ts) => (
        <li className="dbh-ts" key={ts.name}>
          <div className="dbh-ts-head">
            <span className="dbh-ts-name">{ts.name}</span>
            {ts.type && <span className="dbh-ts-type">{ts.type.toLowerCase()}</span>}
            <span className="dbh-ts-figure">
              {formatMb(ts.usedMb)} <span className="dbh-ts-of">of</span> {formatMb(ts.totalMb)}
            </span>
          </div>

          <div
            className="dbh-ts-track"
            role="img"
            aria-label={`${ts.name}: ${ts.pctUsed} percent of allocated space used, ${
              USAGE_WORD[ts.level] || ts.level
            }`}
          >
            <span
              className={`dbh-ts-fill dbh-ts-fill--${ts.level}`}
              style={{ width: `${Math.max(0, Math.min(100, ts.pctUsed || 0))}%` }}
            />
          </div>

          <div className="dbh-ts-foot">
            <span className={`dbh-level dbh-level--${ts.level}`}>
              {USAGE_WORD[ts.level] || ts.level}
            </span>

            <span className="dbh-ts-note">
              {ts.pctUsed}% of allocated
              {ts.canGrow
                ? ` · can extend to ${formatMb(ts.maxMb)}, ${ts.pctOfMax}% of that used`
                : " · fixed size, cannot extend"}
            </span>
          </div>
        </li>
      ))}
    </ul>
  );
}

export default function DbHealthPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const agentName = (searchParams.get("agent") || "").trim();
  const engine = (searchParams.get("engine") || "").trim();
  const serviceName = (searchParams.get("service") || "").trim();

  const [limit, setLimit] = useState(DEFAULT_LIMIT);
  const [compact, setCompact] = useState(false);
  const [status, setStatus] = useState("loading"); // loading | ready | error
  const [error, setError] = useState("");
  const [payload, setPayload] = useState(null);
  const [selected, setSelected] = useState(0);
  const [showRaw, setShowRaw] = useState(false);
  const [showEmptyFields, setShowEmptyFields] = useState(false);
  const [fieldFilter, setFieldFilter] = useState("");
  const [tab, setTab] = useState("overview");
  const tabsRef = useRef(null);

  /**
   * Open a group, and bring its tabs back with it.
   *
   * A tab deep in a long page would otherwise leave the reader looking at the
   * middle of a group they did not choose, with no way back in sight.
   */
  const openGroup = (id) => {
    setTab(id);
    // Guarded: scrollIntoView is a convenience, and not every renderer the
    // component runs in has one — jsdom does not. Losing the scroll must never
    // cost the reader the tab they asked for.
    const bar = tabsRef.current;
    if (bar && typeof bar.scrollIntoView === "function") {
      bar.scrollIntoView({ block: "start", behavior: "smooth" });
    }
  };

  const load = useCallback(
    async (nextLimit, nextCompact) => {
      if (!agentName || !engine) {
        setError("This page needs an agent, an engine and a service in its address.");
        setStatus("error");
        return;
      }

      setStatus("loading");
      setError("");

      try {
        const res = await api.get("/api/db/data", {
          params: {
            agent_name: agentName,
            engine,
            service_name: serviceName || undefined,
            limit: nextLimit,
            compact: nextCompact,
          },
          skipGlobalLoader: true,
        });
        setPayload((res.data && res.data.data) || null);
        setSelected(0);
        setStatus("ready");
      } catch (err) {
        const code = err.response && err.response.status;
        const detail = err.response && err.response.data && err.response.data.detail;
        setError(
          code === 404
            ? detail ||
                "No stored data yet for this database — it may not have been inspected."
            : detail || "Could not read the stored data."
        );
        setStatus("error");
      }
    },
    [agentName, engine, serviceName]
  );

  useEffect(() => {
    load(DEFAULT_LIMIT, false);
  }, [load]);

  // Not payload.rows: that is sometimes another envelope rather than a list.
  const rows = useMemo(() => unwrapRows(payload), [payload]);
  const record = rows[selected] || null;

  const { checks, fields } = useMemo(() => splitRecord(record), [record]);

  // Only the figures this record actually carries, and the reason there are
  // none when a database was detected but never connected to.
  const stats = useMemo(() => pickStats(record), [record]);
  const ratios = useMemo(() => hitRatios(record), [record]);
  const spaces = useMemo(() => tablespaces(record), [record]);
  const expiring = useMemo(() => expiringAccounts(record), [record]);
  const blocked = useMemo(() => blockedSessions(record), [record]);
  const limits = useMemo(() => resourceLimits(record), [record]);
  const memory = useMemo(() => memoryBreakdown(record), [record]);
  const unusable = useMemo(() => unusableIndexes(record), [record]);

  // Lead checks first, the rest in the order the API sent them.
  const orderedChecks = useMemo(() => {
    const drawn = ownSection({ ratios, spaces, blocked, limits, memory });
    const lead = [];
    const rest = [];
    checks.forEach((entry) => {
      if (drawn.includes(entry[0])) return;
      (LEAD_CHECKS.includes(entry[0]) ? lead : rest).push(entry);
    });
    lead.sort((a, b) => LEAD_CHECKS.indexOf(a[0]) - LEAD_CHECKS.indexOf(b[0]));
    return [...lead, ...rest];
  }, [checks, ratios, spaces, blocked, limits, memory]);

  // Forty-three cards is not a page; the same cards behind six named tabs are.
  const groups = useMemo(() => groupChecks(orderedChecks), [orderedChecks]);

  // A record from another engine may not have the group the last one did.
  const activeGroup = groups.find((g) => g.id === tab) || groups[0] || null;

  const notice = useMemo(() => inspectionNotice(record), [record]);
  const { present: liveFields, empty: emptyFields } = useMemo(
    () => partitionFields(fields),
    [fields]
  );

  // What the record table shows: the fields that carry something, the empty
  // ones when asked for, and only what matches the filter.
  const recordFields = useMemo(
    () => (showEmptyFields ? [...liveFields, ...emptyFields] : liveFields),
    [showEmptyFields, liveFields, emptyFields]
  );

  const visibleFields = useMemo(() => {
    const needle = fieldFilter.trim().toLowerCase();
    if (!needle) return recordFields;
    return recordFields.filter(
      ([key, value]) =>
        titleOf(key).toLowerCase().includes(needle) ||
        String(value == null ? "" : value).toLowerCase().includes(needle)
    );
  }, [recordFields, fieldFilter]);

  const onSubmit = (e) => {
    e.preventDefault();
    // The endpoint rejects anything outside 1..500, so clamp rather than fail.
    const clamped = Math.min(LIMIT_MAX, Math.max(LIMIT_MIN, Number(limit) || LIMIT_MIN));
    setLimit(clamped);
    load(clamped, compact);
  };

  return (
    <div className="dbh-page">
      <header className="dbh-head">
        <div className="dbh-head-main">
          <button
            type="button"
            className="dbh-back phi-btn phi-btn--sm phi-btn--secondary"
            onClick={() => navigate("/app/dashboard")}
          >
            ← Dashboard
          </button>

          <h1 className="dbh-title">
            {serviceName || (payload && payload.service_name) || "Database"}
            {record && record.health_status ? (
              <span className={`dbh-badge dbh-badge--${healthTone(record.health_status)}`}>
                {record.health_status}
              </span>
            ) : (
              // No health status is not the same as unhealthy — say which it is.
              record &&
              record.inspected === false && (
                <span className="dbh-badge dbh-badge--muted">Not inspected</span>
              )
            )}
          </h1>

          {/* Facts as separate pills rather than one dot-separated sentence —
              each one is looked up on its own, not read start to finish. */}
          <div className="dbh-sub">
            <span className="dbh-engine">{engine || "—"}</span>

            <span className="dbh-meta">
              <span className="dbh-meta-key">agent</span>
              {agentName || "—"}
            </span>

            {record && record.db_host && (
              <span className="dbh-meta">
                <span className="dbh-meta-key">host</span>
                <span className="dbh-mono">
                  {record.db_host}
                  {record.db_port ? `:${record.db_port}` : ""}
                </span>
              </span>
            )}

            {record && record.db_version && (
              <span className="dbh-meta">
                <span className="dbh-meta-key">version</span>
                {record.db_version}
              </span>
            )}

            {record && record.database_role && (
              <span className="dbh-meta">
                <span className="dbh-meta-key">role</span>
                {record.database_role}
              </span>
            )}

            {record && record.open_mode && (
              <span className="dbh-meta">
                <span className="dbh-meta-key">open mode</span>
                {record.open_mode}
              </span>
            )}

            {record && record.is_cdb != null && (
              <span className="dbh-meta dbh-meta--soft">
                {record.is_cdb ? "container database" : "not a container database"}
              </span>
            )}

            {record && record.timestamp && (
              <span className="dbh-meta">
                <span className="dbh-meta-key">read</span>
                {formatTimestamp(record.timestamp)}
              </span>
            )}

            {payload && payload.matched_on && (
              <span className="dbh-meta dbh-meta--soft">
                matched on {titleOf(payload.matched_on).toLowerCase()}
              </span>
            )}
          </div>
        </div>

        {/* The two things the endpoint lets a reader change. Said in the
            reader's words rather than the API's: "limit" is how many stored
            readings to fetch, and "compact" asks it to leave out the columns
            that are empty in every one of them. */}
        <form className="dbh-controls" onSubmit={onSubmit}>
          <div className="dbh-ctl">
            <label className="dbh-ctl-label" htmlFor="dbh-limit">
              Readings
            </label>

            <input
              id="dbh-limit"
              className="dbh-ctl-input"
              type="number"
              value={limit}
              min={LIMIT_MIN}
              max={LIMIT_MAX}
              aria-describedby="dbh-limit-hint"
              onChange={(e) => setLimit(e.target.value)}
              disabled={status === "loading"}
            />

            <span className="dbh-ctl-hint" id="dbh-limit-hint">
              {LIMIT_MIN}–{LIMIT_MAX}
            </span>
          </div>

          <label className="dbh-ctl-check">
            <input
              type="checkbox"
              checked={compact}
              onChange={(e) => setCompact(e.target.checked)}
              disabled={status === "loading"}
            />
            <span>Hide empty columns</span>
          </label>

          <button
            type="submit"
            className="dbh-load phi-btn phi-btn--sm"
            disabled={status === "loading"}
          >
            {status === "loading" ? (
              <>
                <span className="phi-spinner" aria-hidden="true" />
                Loading…
              </>
            ) : (
              "Load"
            )}
          </button>
        </form>
      </header>

      {status === "loading" && <div className="dbh-status">Reading stored data…</div>}

      {status === "error" && (
        <div className="dbh-status dbh-status--error" role="alert">
          {error}
        </div>
      )}

      {status === "ready" && rows.length === 0 && (
        <div className="dbh-status">Nothing stored for this database.</div>
      )}

      {status === "ready" && record && (
        <>
          {/* A time series: pick which reading to read. */}
          {rows.length > 1 && (
            <div className="dbh-history" role="tablist" aria-label="Stored readings">
              {rows.map((row, i) => (
                <button
                  key={row.id ?? i}
                  type="button"
                  role="tab"
                  aria-selected={i === selected}
                  className={`dbh-history-item ${i === selected ? "active" : ""}`}
                  onClick={() => setSelected(i)}
                >
                  {formatTimestamp(row.timestamp)}
                </button>
              ))}
            </div>
          )}

          {/* Why every figure is missing, said once and at the top, rather
              than left for the reader to infer from a page of dashes. */}
          {notice && (
            <section className="dbh-notice" role="status">
              <span className="dbh-notice-icon" aria-hidden="true">
                !
              </span>

              <div className="dbh-notice-body">
                <h2 className="dbh-notice-title">{notice.title}</h2>

                <p className="dbh-notice-detail">{notice.detail}</p>

                {notice.target && (
                  <p className="dbh-notice-target">
                    Target <span className="dbh-mono">{notice.target}</span>
                    {record.db_host && (
                      <>
                        {" · "}
                        <span className="dbh-mono">
                          {record.db_host}
                          {record.db_port ? `:${record.db_port}` : ""}
                        </span>
                      </>
                    )}
                  </p>
                )}
              </div>
            </section>
          )}

          {/* What the agent did, in its own words: the four fields that say
              which collector ran, what it did and how it turned out. */}
          <div className="dbh-chips">
            {record.action && (
              <span className="dbh-chip">
                <span className="dbh-chip-key">action</span>
                {record.action}
              </span>
            )}
            {record.outcome && (
              <span
                className={`dbh-chip dbh-chip--${
                  record.outcome === "success" ? "ok" : "bad"
                }`}
              >
                <span className="dbh-chip-key">outcome</span>
                {record.outcome}
              </span>
            )}
            {record.severity && (
              <span className={`dbh-chip dbh-chip--${healthTone(record.severity)}`}>
                <span className="dbh-chip-key">severity</span>
                {record.severity}
              </span>
            )}
            {record.collector && (
              <span className="dbh-chip">
                <span className="dbh-chip-key">collector</span>
                {record.collector}
              </span>
            )}
            {record.inspected != null && (
              <span className="dbh-chip">
                <span className="dbh-chip-key">inspected</span>
                {record.inspected ? "yes" : "no"}
              </span>
            )}
          </div>

          {stats.length > 0 && (
            <div className="dbh-stats">
              {stats.map((stat) => (
                <Stat
                  key={stat.label}
                  label={stat.label}
                  value={stat.value}
                  sub={stat.sub}
                  tone={stat.tone}
                />
              ))}
            </div>
          )}

          {blocked.length > 0 && (
            <section className="dbh-card dbh-card--blocked">
              <h3 className="dbh-card-title">
                Sessions blocked
                <span className="dbh-card-count">{blocked.length}</span>
              </h3>
              <p className="dbh-card-lead">
                Someone is waiting on someone else's lock right now. Everything else on
                this page is a measurement; this is a queue.
              </p>

              <BlockedList rows={blocked} />
            </section>
          )}

          {unusable.length > 0 && (
            <section className="dbh-card dbh-card--unusable">
              <h3 className="dbh-card-title">
                Unusable indexes
                <span className="dbh-card-count">{unusable.length}</span>
              </h3>
              <p className="dbh-card-lead">
                The optimiser cannot use these until they are rebuilt, so queries that
                depend on them are scanning instead.
              </p>

              <ul className="dbh-expiry-list">
                {unusable.map((index) => (
                  <li className="dbh-expiry" key={`${index.owner}.${index.name}`}>
                    <span className="dbh-level dbh-level--bad">{index.status.toLowerCase()}</span>
                    <span className="dbh-expiry-user">{index.name}</span>
                    <span className="dbh-expiry-status">{index.owner}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* The quiet one. An expiring password breaks a running application
              at a moment nobody chose, so it is said before the figures. */}
          {expiring.length > 0 && (
            <section className="dbh-card dbh-card--expiring">
              <h3 className="dbh-card-title">Passwords expiring</h3>

              <ul className="dbh-expiry-list">
                {expiring.map((account) => (
                  <li className="dbh-expiry" key={account.username}>
                    <span className={`dbh-level dbh-level--${account.level}`}>
                      {account.days <= 0
                        ? "expired"
                        : `${account.days} day${account.days === 1 ? "" : "s"}`}
                    </span>

                    <span className="dbh-expiry-user">{account.username}</span>

                    {account.status && (
                      <span className="dbh-expiry-status">{account.status.toLowerCase()}</span>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* Two readings that are ratios against a limit, so they are drawn
              as meters rather than buried as numbers in the field table. */}
          {ratios.length > 0 && (
            <section className="dbh-card dbh-card--meters">
              <h3 className="dbh-card-title">Cache hit ratios</h3>
              <p className="dbh-card-lead">
                How often the database answered from memory instead of going to disk.
                Sustained figures under 90% usually mean it needs more memory.
              </p>

              <div className="dbh-meters">
                {ratios.map((r) => (
                  <Meter
                    key={r.label}
                    label={r.label}
                    value={r.value}
                    hint={r.hint}
                    level={r.level}
                  />
                ))}
              </div>
            </section>
          )}

          {limits.length > 0 && (
            <section className="dbh-card dbh-card--limits">
              <h3 className="dbh-card-title">
                Resource limits
                <span className="dbh-card-count">{limits.length}</span>
              </h3>
              <p className="dbh-card-lead">
                The bar is where each resource is now; the notch is the highest it has
                reached since startup. The notch is what decides whether a busy afternoon
                starts refusing connections.
              </p>

              <LimitList rows={limits} />
            </section>
          )}

          {memory && (
            <section className="dbh-card dbh-card--memory">
              <h3 className="dbh-card-title">Memory</h3>
              <p className="dbh-card-lead">
                What the instance has, and what it is spent on — the buffer cache and the
                shared pool are both inside the SGA, not beside it.
              </p>

              <MemoryPanel memory={memory} />
            </section>
          )}

          {spaces.length > 0 && (
            <section className="dbh-card dbh-card--spaces">
              <h3 className="dbh-card-title">
                Tablespaces
                <span className="dbh-card-count">{spaces.length}</span>
              </h3>
              <p className="dbh-card-lead">
                Most pressed first. A tablespace that can still autoextend is judged on
                the room it can still take, not on how full its current datafiles are.
              </p>

              <TablespaceList items={spaces} />
            </section>
          )}

          {/* Everything above this line is either an alarm or a figure, and
              stays put. Below it is the detail, which is where the length was:
              one tab at a time instead of thirteen thousand pixels at once. */}
          {groups.length > 0 && (
            <>
              <div className="dbh-tabs" ref={tabsRef} role="tablist" aria-label="Checks">
                {groups.map((group) => (
                  <button
                    key={group.id}
                    type="button"
                    role="tab"
                    id={`dbh-tab-${group.id}`}
                    aria-selected={activeGroup && group.id === activeGroup.id}
                    aria-controls={`dbh-panel-${group.id}`}
                    className={`dbh-tab ${
                      activeGroup && group.id === activeGroup.id ? "active" : ""
                    }`}
                    onClick={() => openGroup(group.id)}
                  >
                    {group.label}
                    {/* the count is what makes a closed tab legible */}
                    <span className="dbh-tab-count">{group.entries.length}</span>
                  </button>
                ))}
              </div>

              {activeGroup && (
                <div
                  className="dbh-cards"
                  role="tabpanel"
                  id={`dbh-panel-${activeGroup.id}`}
                  aria-labelledby={`dbh-tab-${activeGroup.id}`}
                >
                  {activeGroup.entries.map(([name, value]) => (
                    <CheckCard
                      key={name}
                      name={name}
                      value={value}
                      chart={chartFor(name, record)}
                    />
                  ))}
                </div>
              )}
            </>
          )}

          {/* The record itself is a flat list of ~50 named values, which is
              what a table is for: one row each, one column of names to scan
              down, and a filter for when the name is already known. */}
          <section className="dbh-card dbh-card--record">
            <h3 className="dbh-card-title">
              Record
              <span className="dbh-card-count">
                {visibleFields.length}
                {visibleFields.length !== recordFields.length &&
                  ` of ${recordFields.length}`}
              </span>

              <input
                type="search"
                className="dbh-filter"
                placeholder="Filter fields…"
                aria-label="Filter record fields"
                value={fieldFilter}
                onChange={(e) => setFieldFilter(e.target.value)}
              />
            </h3>

            <RecordTable entries={visibleFields} />

            {/* The nulls are kept, not hidden for good: which checks came back
                empty is itself an answer, just not the first one to show. */}
            {emptyFields.length > 0 && (
              <button
                type="button"
                className="dbh-empty-toggle phi-btn phi-btn--sm phi-btn--secondary"
                onClick={() => setShowEmptyFields((v) => !v)}
                aria-expanded={showEmptyFields}
              >
                {showEmptyFields
                  ? `Hide ${emptyFields.length} empty fields`
                  : `Show ${emptyFields.length} empty fields`}
              </button>
            )}
          </section>

          <div className="dbh-raw">
            <button
              type="button"
              className="dbh-raw-toggle phi-btn phi-btn--sm phi-btn--secondary"
              onClick={() => setShowRaw((v) => !v)}
              aria-expanded={showRaw}
            >
              {showRaw ? "Hide raw JSON" : "Show raw JSON"}
            </button>
            {showRaw && <pre className="dbh-raw-body">{JSON.stringify(record, null, 2)}</pre>}
          </div>
        </>
      )}
    </div>
  );
}
