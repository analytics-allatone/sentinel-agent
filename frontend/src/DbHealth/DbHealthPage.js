import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import api from "../api/api";
import {
  columnsOf,
  formatTimestamp,
  formatValue,
  healthTone,
  inspectionNotice,
  isRowArray,
  partitionFields,
  pickStats,
  splitRecord,
  titleOf,
} from "./dbHealthFormat";
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

/** A list of objects, as a table. */
function RowTable({ rows }) {
  const columns = columnsOf(rows);
  return (
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
          {rows.map((row, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c} title={String(row[c] ?? "")}>
                  {formatValue(c, row[c])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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

/** One check: its scalars first, then each nested list as its own table. */
function CheckCard({ name, value }) {
  if (isRowArray(value)) {
    return (
      <section className="dbh-card">
        <h3 className="dbh-card-title">
          {titleOf(name)}
          <span className="dbh-card-count">{value.length}</span>
        </h3>
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

  const rows = useMemo(() => (payload && payload.rows) || [], [payload]);
  const record = rows[selected] || null;

  const { checks, fields } = useMemo(() => splitRecord(record), [record]);

  // Lead checks first, the rest in the order the API sent them.
  const orderedChecks = useMemo(() => {
    const lead = [];
    const rest = [];
    checks.forEach((entry) => {
      (LEAD_CHECKS.includes(entry[0]) ? lead : rest).push(entry);
    });
    lead.sort((a, b) => LEAD_CHECKS.indexOf(a[0]) - LEAD_CHECKS.indexOf(b[0]));
    return [...lead, ...rest];
  }, [checks]);

  // Only the figures this record actually carries, and the reason there are
  // none when a database was detected but never connected to.
  const stats = useMemo(() => pickStats(record), [record]);
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
            className="dbh-back"
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

        <form className="dbh-controls" onSubmit={onSubmit}>
          <label className="dbh-field-ctl">
            <span>Limit</span>
            <input
              type="number"
              value={limit}
              min={LIMIT_MIN}
              max={LIMIT_MAX}
              onChange={(e) => setLimit(e.target.value)}
              disabled={status === "loading"}
            />
            <span className="dbh-hint">1–500</span>
          </label>

          <label className="dbh-check-ctl">
            <input
              type="checkbox"
              checked={compact}
              onChange={(e) => setCompact(e.target.checked)}
              disabled={status === "loading"}
            />
            <span>Compact</span>
            <span className="dbh-hint">drop null columns</span>
          </label>

          <button type="submit" className="dbh-load" disabled={status === "loading"}>
            {status === "loading" ? "Loading…" : "Load"}
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

          <div className="dbh-cards">
            {orderedChecks.map(([name, value]) => (
              <CheckCard key={name} name={name} value={value} />
            ))}
          </div>

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
                className="dbh-empty-toggle"
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
              className="dbh-raw-toggle"
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
