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

/** Health wording -> the tone it should be shown in. */
export function healthTone(status) {
  const value = String(status || "").toLowerCase();
  if (["healthy", "ok", "up", "good"].includes(value)) return "ok";
  if (["degraded", "warning", "warn"].includes(value)) return "warn";
  if (["down", "critical", "error", "failed"].includes(value)) return "bad";
  return "muted";
}
