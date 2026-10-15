/**
 * The parts of the record that are worth a picture.
 *
 * Three of the lists the engine sends are rankings — the SQL that took the most
 * time, the segments holding the most bytes — and one is a series over days.
 * Read as tables they are twenty rows of near-identical numbers; drawn, the
 * shape of the distribution is the whole answer ("one statement is most of the
 * elapsed time" / "every segment is about the same size").
 *
 * Everything here is data preparation only: no rendering, so the thresholds and
 * the ordering can be tested without a DOM.
 */
import { formatBytes } from "./dbHealthFormat";

/** How many bars a ranking gets. Past about eight the chart becomes the table. */
export const CHART_ROWS = 8;

/** 1,284 / 12.9K / 4.2M — a tile's worth of digits, not a ledger's. */
export function compactNumber(value) {
  // Number(null) and Number("") are both 0, which would print a figure the
  // database never reported.
  if (value === null || value === undefined || value === "") return "—";
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  const abs = Math.abs(n);
  if (abs >= 1e9) return `${Number((n / 1e9).toFixed(1))}B`;
  if (abs >= 1e6) return `${Number((n / 1e6).toFixed(1))}M`;
  if (abs >= 1e4) return `${Number((n / 1e3).toFixed(1))}K`;
  return n.toLocaleString();
}

/** Seconds, at the precision the figure deserves: 6.42s, 0.99s, 240ms. */
export function formatSeconds(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  if (n < 1) return `${Math.round(n * 1000)}ms`;
  if (n < 60) return `${Number(n.toFixed(2))}s`;
  const minutes = Math.floor(n / 60);
  return `${minutes}m ${Math.round(n % 60)}s`;
}

/**
 * A ranking, scaled so every bar is a share of the largest.
 *
 * The bars are proportional to the top value rather than to an axis maximum:
 * these lists are already sorted and what the reader is after is "how far ahead
 * is the first one", which a share-of-max answers directly.
 */
function ranked(rows, { label, sub, metric, format, title }) {
  const items = (rows || [])
    .map((row) => ({
      label: label(row),
      sub: sub ? sub(row) : "",
      title: title ? title(row) : "",
      value: Number(metric(row)),
    }))
    .filter((item) => Number.isFinite(item.value) && item.value > 0)
    .sort((a, b) => b.value - a.value);

  const top = items.length ? items[0].value : 0;
  return items.slice(0, CHART_ROWS).map((item) => ({
    ...item,
    display: format(item.value),
    share: top > 0 ? (item.value / top) * 100 : 0,
  }));
}

/** The statements that spent the most time, by SQL id. */
export function topSqlByTime(record) {
  return ranked((record && record.top_sql_elapsed) || [], {
    label: (r) => r.sql_id,
    sub: (r) => `${compactNumber(r.executions)} runs · ${r.avg_ms}ms avg`,
    title: (r) => String(r.sql_text || "").trim(),
    metric: (r) => r.elapsed_s,
    format: formatSeconds,
  });
}

/** The statements that ran the most times — a different list, and a different worry. */
export function topSqlByRuns(record) {
  return ranked((record && record.top_sql_executions) || [], {
    label: (r) => r.sql_id,
    sub: (r) => `${formatSeconds(r.elapsed_s)} total · ${r.avg_ms}ms avg`,
    title: (r) => String(r.sql_text || "").trim(),
    metric: (r) => r.executions,
    format: compactNumber,
  });
}

/** Where the bytes actually are. */
export function topSegments(record) {
  return ranked((record && record.top_segments) || [], {
    label: (r) => r.segment_name,
    sub: (r) => `${r.owner} · ${String(r.segment_type || "").toLowerCase()}`,
    metric: (r) => r.total_size_bytes,
    format: formatBytes,
  });
}

/**
 * Archive log volume per day.
 *
 * Kept in date order, not sorted by size: this is the one series on the page
 * where the reader is asking "is it growing?", and a chart sorted by value
 * cannot answer that.
 */
export function archiveSeries(record) {
  const days = (record && record.archive_log_daily) || [];
  if (!Array.isArray(days) || days.length === 0) return [];

  const points = days
    .map((d) => ({
      day: d.day,
      name: d.day_name,
      archives: Number(d.archives),
      mb: Number(d.size_mb),
    }))
    .filter((p) => Number.isFinite(p.mb))
    .sort((a, b) => String(a.day).localeCompare(String(b.day)));

  const top = Math.max(...points.map((p) => p.mb), 0);
  return points.map((p) => ({ ...p, share: top > 0 ? (p.mb / top) * 100 : 0 }));
}

/**
 * Accounts whose password is about to expire.
 *
 * `days_to_expire` is the field nobody reads until an application stops being
 * able to log in, so it gets said out loud rather than left in a table.
 */
export function expiringAccounts(record, within = 30) {
  return ((record && record.user_accounts) || [])
    .filter((u) => Number.isFinite(Number(u.days_to_expire)) && Number(u.days_to_expire) <= within)
    .map((u) => ({
      username: u.username,
      days: Number(u.days_to_expire),
      status: u.account_status,
      level: Number(u.days_to_expire) <= 7 ? "bad" : "warn",
    }))
    .sort((a, b) => a.days - b.days);
}
