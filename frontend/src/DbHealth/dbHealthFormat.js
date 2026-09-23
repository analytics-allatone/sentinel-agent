/**
 * Formatting for stored database health records.
 *
 * The payload is engine-shaped: MySQL sends buffer-pool figures, Postgres sends
 * vacuum and wraparound ones, Redis sends neither. Nothing here assumes a fixed
 * set of keys — the helpers work off the key's *name* and the value's type, so a
 * record from an engine nobody has looked at yet still renders sensibly.
 */

/** "16384" -> "16 KB". Sizes arrive as raw bytes on every engine. */
export function formatBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  if (n === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(Math.abs(n)) / Math.log(1024)));
  const scaled = n / 1024 ** i;
  // One decimal where it says something, none where it would only add ".0"
  const rounded = scaled >= 100 || i === 0 ? Math.round(scaled) : Number(scaled.toFixed(1));
  return `${rounded} ${units[i]}`;
}

/** "259465" -> "3d 0h 4m". Uptimes and durations both arrive in seconds. */
export function formatDuration(value) {
  const total = Number(value);
  if (!Number.isFinite(total)) return "—";
  if (total < 1) return "under a second";

  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = Math.floor(total % 60);

  if (days) return `${days}d ${hours}h ${minutes}m`;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

/** ISO instant -> "14 Sep 2026, 16:51" in the reader's own zone. */
export function formatTimestamp(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Turn a wire key into a heading: "cache_hit_ratio" -> "Cache hit ratio". */
export function titleOf(key) {
  const text = String(key || "").replace(/[_-]+/g, " ").trim();
  if (!text) return "";
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/**
 * One value, formatted by what its key says it is.
 *
 * `*_bytes` is a size, `*_seconds` a duration, `*_pct` a percentage, and
 * anything ending in `_at`/`time`/`timestamp` an instant. Everything else is
 * printed as it came, because guessing further would misstate it.
 */
export function formatValue(key, value) {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";

  const name = String(key || "").toLowerCase();
  if (typeof value === "number") {
    if (name.endsWith("_bytes")) return formatBytes(value);
    if (name.endsWith("_seconds")) return formatDuration(value);
    if (name.endsWith("_pct") || name.endsWith("_percent")) return `${value}%`;
    return value.toLocaleString();
  }

  if (typeof value === "string") {
    if (/(_at|_time|timestamp)$/.test(name) && !Number.isNaN(Date.parse(value))) {
      return formatTimestamp(value);
    }
    return value;
  }

  if (Array.isArray(value)) return value.map((v) => String(v)).join(", ");
  return JSON.stringify(value);
}

/** An array of plain objects renders as a table; anything else does not. */
export function isRowArray(value) {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((v) => v && typeof v === "object" && !Array.isArray(v))
  );
}

/** Every column across the rows, in first-seen order. */
export function columnsOf(rows) {
  const seen = [];
  (rows || []).forEach((row) => {
    Object.keys(row || {}).forEach((key) => {
      if (!seen.includes(key)) seen.push(key);
    });
  });
  return seen;
}

/**
 * Split a record into the checks (nested results) and the record's own fields.
 *
 * The division is by shape, not by a hard-coded key list: a check is an object
 * or a list, a field is a scalar. That keeps engines this code has never seen
 * rendering in the right half of the page.
 */
export function splitRecord(record) {
  const checks = [];
  const fields = [];

  Object.entries(record || {}).forEach(([key, value]) => {
    if (value !== null && typeof value === "object") checks.push([key, value]);
    else fields.push([key, value]);
  });

  return { checks, fields };
}

/**
 * The headline figures this record actually carries.
 *
 * Engines put the same figure in different places — MySQL nests the summary
 * under `health_summary`, Oracle puts sessions and cache at the top level — so
 * each stat names every place it can live and takes the first that is there.
 *
 * A figure that is absent is left out rather than shown as a dash: a row of
 * dashes says "this page is broken", when the truth is "nothing was measured".
 */
const STAT_SOURCES = [
  { label: "Database size", keys: ["db_size_bytes", "total_size_bytes"], as: "bytes" },
  { label: "Sessions", keys: ["total_connections", "sessions_current"] },
  { label: "Active", keys: ["active_queries", "sessions_active"] },
  { label: "Blocked", keys: ["sessions_blocked"], badWhenPositive: true },
  { label: "Uptime", keys: ["uptime_seconds"], as: "duration" },
  { label: "Tables", keys: ["table_count"] },
  { label: "Databases", keys: ["database_count"] },
  { label: "Role", keys: ["database_role"] },
  { label: "Open mode", keys: ["open_mode"] },
];

function firstPresent(sources, keys) {
  for (const key of keys) {
    for (const source of sources) {
      const value = source && source[key];
      if (value !== null && value !== undefined && value !== "") return value;
    }
  }
  return undefined;
}

export function pickStats(record) {
  if (!record) return [];

  const summary = record.health_summary || {};
  const sources = [summary, record];
  const stats = [];

  STAT_SOURCES.forEach((stat) => {
    const value = firstPresent(sources, stat.keys);
    if (value === undefined) return;

    stats.push({
      label: stat.label,
      value:
        stat.as === "bytes"
          ? formatBytes(value)
          : stat.as === "duration"
            ? formatDuration(value)
            : formatValue(stat.keys[0], value),
      sub: stat.label === "Database size" ? summary.current_database : undefined,
      tone: stat.badWhenPositive && Number(value) > 0 ? "bad" : undefined,
    });
  });

  // Cache hit lives in its own check on MySQL and at the top level on Oracle.
  const cache = record.cache_hit_ratio || {};
  const cacheHit =
    cache.buffer_pool_hit_pct != null ? cache.buffer_pool_hit_pct : record.cache_hit_pct;
  if (cacheHit != null) {
    stats.push({
      label: "Cache hit",
      value: `${cacheHit}%`,
      sub: cache.read_requests != null
        ? `${Number(cache.read_requests).toLocaleString()} reads`
        : undefined,
      tone: Number(cacheHit) >= 95 ? "ok" : "warn",
    });
  }

  // "0 issues" is only good news when something was actually checked; on a
  // record that was never inspected it is a claim nobody made.
  if (Array.isArray(record.issues) && (record.issues.length > 0 || record.inspected !== false)) {
    stats.push({
      label: "Issues",
      value: record.issues.length,
      tone: record.issues.length ? "bad" : "ok",
    });
  }

  return stats;
}

/**
 * The one thing worth saying at the top when a record carries no measurements.
 *
 * `inspected: false` means the agent found the database and wrote it down, but
 * never connected to it — every check is null for a reason, and `notes` is that
 * reason. Without this the page reads as broken instead of as "not collected".
 */
export function inspectionNotice(record) {
  if (!record || record.inspected !== false) return null;

  return {
    title: "Detected, but not inspected",
    detail:
      record.notes ||
      "The agent recorded this database but did not collect health data from it.",
    target: record.target_name || "",
  };
}

/** Fields worth reading, and the ones that only say "nothing here". */
export function partitionFields(fields) {
  const present = [];
  const empty = [];

  (fields || []).forEach((entry) => {
    const value = entry[1];
    (value === null || value === undefined || value === "" ? empty : present).push(entry);
  });

  return { present, empty };
}

/** Health wording -> the tone it should be shown in. */
export function healthTone(status) {
  const value = String(status || "").toLowerCase();
  if (["healthy", "ok", "up", "good"].includes(value)) return "ok";
  if (["degraded", "warning", "warn"].includes(value)) return "warn";
  if (["down", "critical", "error", "failed"].includes(value)) return "bad";
  return "muted";
}
