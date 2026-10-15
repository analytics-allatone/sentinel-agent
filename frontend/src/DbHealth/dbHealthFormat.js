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

/**
 * Turn a wire key into a heading: "cache_hit_ratio" -> "Cache hit ratio".
 *
 * The unit suffix comes off, because the value carries it: formatValue already
 * renders `total_size_bytes` as "947 MB", and "Total size bytes: 947 MB" then
 * names a unit the number is not in.
 */
const UNIT_SUFFIX = /_(bytes|seconds|pct|percent)$/;

export function titleOf(key) {
  const text = String(key || "")
    .replace(UNIT_SUFFIX, "")
    .replace(/[_-]+/g, " ")
    .trim();
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
  if (isBlank(value)) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";

  const name = String(key || "").toLowerCase();
  if (typeof value === "number") {
    if (name.endsWith("_bytes")) return formatBytes(value);
    if (name.endsWith("_seconds")) return formatDuration(value);
    if (name.endsWith("_pct") || name.endsWith("_percent")) return `${value}%`;
    return value.toLocaleString();
  }

  if (typeof value === "string") {
    // The shape of the value decides, not the name of the key. Going by the
    // key turned pwd_life_time: "180" — a number of days — into "Jan 01, 180",
    // because Date.parse will happily read a bare number as a year.
    if (/^\d{4}-\d{2}-\d{2}T/.test(value) && !Number.isNaN(Date.parse(value))) {
      return formatTimestamp(value);
    }
    // A date with no time of day does not get one invented for it.
    if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
      const date = new Date(`${value}T00:00:00`);
      if (!Number.isNaN(date.getTime())) {
        return date.toLocaleDateString(undefined, {
          day: "2-digit",
          month: "short",
          year: "numeric",
        });
      }
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
 * Eleven tiles of equal weight is a list, not a summary: "Role: PRIMARY" and
 * "Sessions: 1" were drawn the same size although only one of them is a
 * measurement. So the tiles now hold the five figures that change between one
 * reading and the next, each with the context that makes it mean something —
 * sessions with their breakdown, size with what is in it, uptime with the
 * instant it started from. The constant facts (role, open mode, container)
 * moved up into the header, where facts belong.
 *
 * Engines put the same figure in different places — MySQL nests the summary
 * under `health_summary`, Oracle puts sessions at the top level — so each one
 * names every place it can live and takes the first that is there. A figure
 * that is absent is left out rather than shown as a dash: a row of dashes says
 * "this page is broken", when the truth is "nothing was measured".
 */
function firstPresent(sources, keys) {
  for (const key of keys) {
    for (const source of sources) {
      const value = source && source[key];
      if (value !== null && value !== undefined && value !== "") return value;
    }
  }
  return undefined;
}

/** "1 active · 0 blocked · 0 idle", leaving out whatever was not reported. */
function sessionDetail(parts) {
  return parts
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([word, value]) => `${Number(value).toLocaleString()} ${word}`)
    .join(" · ");
}

/** The instant an uptime counted from, which is what "8h 5m" is really saying. */
export function startedAt(record) {
  const seconds = Number(record && record.uptime_seconds);
  const read = record && record.timestamp ? Date.parse(record.timestamp) : NaN;
  if (!Number.isFinite(seconds) || Number.isNaN(read)) return "";
  return formatTimestamp(new Date(read - seconds * 1000).toISOString());
}

export function pickStats(record) {
  if (!record) return [];

  const summary = record.health_summary || {};
  const sessions = record.session_summary || {};
  const sources = [summary, sessions, record];
  const stats = [];

  const total = firstPresent(sources, [
    "total_connections",
    "sessions_current",
    "total_sessions",
    "total",
  ]);
  if (total !== undefined) {
    const active = firstPresent(sources, ["active_queries", "sessions_active", "active_sessions", "active"]);
    const blocked = firstPresent(sources, ["sessions_blocked", "blocked_sessions", "blocked"]);
    const idle = firstPresent([sessions], ["inactive"]);
    stats.push({
      label: "Sessions",
      value: Number(total).toLocaleString(),
      sub: sessionDetail([
        ["active", active],
        ["blocked", blocked],
        ["idle", idle],
      ]),
      // A blocked session is the one figure here that is never routine.
      tone: Number(blocked) > 0 ? "bad" : undefined,
    });
  }

  const size = firstPresent(sources, ["db_size_bytes", "total_size_bytes"]);
  if (size !== undefined) {
    const tables = firstPresent(sources, ["table_count"]);
    const databases = firstPresent(sources, ["database_count"]);
    const holds = [
      tables !== undefined ? `${Number(tables).toLocaleString()} tables` : "",
      databases !== undefined
        ? `${Number(databases).toLocaleString()} database${Number(databases) === 1 ? "" : "s"}`
        : "",
    ].filter(Boolean);
    stats.push({
      label: "Database size",
      value: formatBytes(size),
      sub: holds.length ? holds.join(" · ") : summary.current_database || undefined,
    });
  }

  const uptime = firstPresent(sources, ["uptime_seconds"]);
  if (uptime !== undefined) {
    const since = startedAt(record);
    stats.push({
      label: "Uptime",
      value: formatDuration(uptime),
      sub: since ? `since ${since}` : undefined,
    });
  }

  // Cache hit lives in its own check on MySQL and at the top level on Oracle.
  const cache = record.cache_hit_ratio || {};
  const cacheHit = firstPresent(
    [cache, record],
    ["buffer_pool_hit_pct", "buffer_cache_hit_ratio", "cache_hit_pct"]
  );
  if (cacheHit !== undefined) {
    stats.push({
      label: "Cache hit",
      value: `${cacheHit}%`,
      sub:
        cache.read_requests != null
          ? `${Number(cache.read_requests).toLocaleString()} reads`
          : "reads served from memory",
      tone: ratioLevel(cacheHit),
    });
  }

  // "0 issues" is only good news when something was actually checked; on a
  // record that was never inspected it is a claim nobody made.
  if (Array.isArray(record.issues) && (record.issues.length > 0 || record.inspected !== false)) {
    stats.push({
      label: "Issues",
      value: record.issues.length,
      sub: record.issues.length ? "needs attention" : "none reported",
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
    (isBlank(value) ? empty : present).push(entry);
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

/* ───────────────────────────────────────────────────────────────
   Oracle's fuller payload — a database that really was inspected
   ─────────────────────────────────────────────────────────────── */

/**
 * The records, however deeply the envelope is wrapped.
 *
 * `/api/db/data` answers `{status, message, data: {engine, count, rows}}` — but
 * when the agent stored an already-wrapped reading, `rows` is itself another
 * whole envelope rather than a list, two or three deep. Reading `payload.rows`
 * straight gives an object, `rows[0]` is undefined, and the page renders empty
 * for a database that reported plenty. So: follow `rows`/`data` down until a
 * real list of records turns up.
 */
export function unwrapRows(payload, depth = 0) {
  if (!payload || typeof payload !== "object" || depth > 6) return [];
  if (Array.isArray(payload)) return payload;

  const { rows, data } = payload;
  if (Array.isArray(rows)) return rows;
  if (rows && typeof rows === "object") return unwrapRows(rows.data || rows, depth + 1);
  if (data && typeof data === "object") return unwrapRows(data, depth + 1);
  return [];
}

/**
 * Empty, including the ways this API spells it.
 *
 * Several checks come back as the four-character string "null" rather than a
 * JSON null — `memory`, `notes`, `details`, `alert_log_errors`. Printed as they
 * came, they read as a value the database reported, which is the opposite of
 * what they mean.
 */
export function isBlank(value) {
  if (value === null || value === undefined || value === "") return true;
  if (typeof value !== "string") return false;
  const text = value.trim().toLowerCase();
  return text === "" || text === "null" || text === "none" || text === "n/a";
}

/**
 * A check that answered in prose: "no RMAN backup jobs in last 7 days".
 *
 * Several Oracle checks report their result as a sentence instead of data.
 * That is a real answer and belongs on the page — just as a note, not as a
 * one-cell table.
 */
export function isProseNote(value) {
  return typeof value === "string" && !isBlank(value) && /\s/.test(value.trim());
}

/** Higher is better: a cache that is missing is the thing worth seeing. */
export function ratioLevel(pct) {
  const n = Number(pct);
  if (!Number.isFinite(n)) return "muted";
  if (n >= 95) return "ok";
  if (n >= 90) return "warn";
  return "bad";
}

/** Higher is worse: space filling up. */
export function usageLevel(pct) {
  const n = Number(pct);
  if (!Number.isFinite(n)) return "muted";
  if (n >= 95) return "bad";
  if (n >= 85) return "warn";
  return "ok";
}

/**
 * Tablespaces, with the distinction that decides whether a full one matters.
 *
 * `pct_used` is of what is allocated *today*. Oracle datafiles normally
 * autoextend, so SYSTEM sitting at 99.65% of 300 MB while `max_mb` is 32 TB is
 * routine — it grows on the next write. Reading that as critical cries wolf on
 * every healthy Oracle instance.
 *
 * So severity follows the headroom that actually exists: `pct_of_max` where the
 * tablespace can still grow, `pct_used` where it cannot. Both numbers are kept,
 * because "94% of what it has, 0% of what it may take" is the honest sentence.
 */
export function tablespaces(record) {
  const list = (record && record.database_sizes) || [];
  if (!Array.isArray(list)) return [];

  return list
    .map((ts) => {
      const totalMb = Number(ts.total_mb);
      const maxMb = Number(ts.max_mb);
      const pctUsed = Number(ts.pct_used);
      const pctOfMax = Number(ts.pct_of_max);
      // A max below or at the current size means this is all it will ever be.
      const canGrow = Number.isFinite(maxMb) && Number.isFinite(totalMb) && maxMb > totalMb;
      const pressure = canGrow ? pctOfMax : pctUsed;

      return {
        name: ts.datname,
        type: ts.ts_type,
        usedMb: Number(ts.used_mb),
        freeMb: Number(ts.free_mb),
        totalMb,
        maxMb,
        pctUsed: Number.isFinite(pctUsed) ? pctUsed : null,
        pctOfMax: Number.isFinite(pctOfMax) ? pctOfMax : null,
        canGrow,
        pressure: Number.isFinite(pressure) ? pressure : null,
        level: usageLevel(pressure),
      };
    })
    // Most pressed first — but to the nearest whole percent. Where everything
    // can autoextend every pressure is a rounding error, and ordering on those
    // put TEMP (0.01% of its maximum, 20% full) above SYSTEM (0%, 99.65% full).
    // Below a percent there is no pressure to rank, so how full the current
    // datafiles are decides instead.
    .sort(
      (a, b) =>
        Math.round(b.pressure ?? -1) - Math.round(a.pressure ?? -1) ||
        (b.pctUsed ?? -1) - (a.pctUsed ?? -1)
    );
}

/** The three Oracle hit ratios, wherever this engine happened to put them. */
export function hitRatios(record) {
  if (!record) return [];
  const ratio = record.cache_hit_ratio || {};

  const sources = [
    {
      label: "Buffer cache",
      value: ratio.buffer_cache_hit_ratio ?? ratio.buffer_pool_hit_pct ?? record.cache_hit_pct,
      hint: "reads served from memory instead of disk",
    },
    {
      label: "Library cache",
      value: ratio.library_hit_ratio ?? record.library_hit_pct,
      hint: "statements reused instead of re-parsed",
    },
    {
      label: "Dictionary cache",
      value: ratio.dictionary_hit_ratio ?? record.dict_hit_pct,
      hint: "metadata lookups served from memory",
    },
  ];

  return sources
    .filter((s) => s.value !== null && s.value !== undefined && Number.isFinite(Number(s.value)))
    .map((s) => ({ ...s, value: Number(s.value), level: ratioLevel(s.value) }));
}

/* ───────────────────────────────────────────────────────────────
   The checks that arrive as a shape of their own
   ─────────────────────────────────────────────────────────────── */

/**
 * Sessions waiting on another session's lock.
 *
 * The one thing on this page that is somebody waiting right now. It arrives as
 * `{blocked: [...]}` on an engine that has contention and as a bare `[]` on one
 * that does not, so both are read the same way.
 */
export function blockedSessions(record) {
  const held = record && record.locks_blocking;
  const list = Array.isArray(held) ? held : (held && held.blocked) || [];

  return list
    .map((row) => ({
      blocked: row.blocked_sid ?? row.blocked ?? row.sid,
      blocker: row.blocking_sid ?? row.blocking_session ?? row.blocker,
      username: row.username || "",
      event: row.event || "",
      waitClass: row.wait_class || "",
      seconds: Number(row.seconds_in_wait ?? row.wait_seconds),
      // A minute of waiting is a stall; a few seconds is ordinary contention.
      level: Number(row.seconds_in_wait ?? row.wait_seconds) >= 60 ? "bad" : "warn",
    }))
    .sort((a, b) => (b.seconds || 0) - (a.seconds || 0));
}

/**
 * How close each resource is to the limit configured for it.
 *
 * Two numbers matter and they answer different questions: `current_utilization`
 * is now, `max_utilization` is the highest it has ever been since startup. A
 * database sitting at 30% that peaked at 95% is one bad afternoon from refusing
 * connections, and only the second number says so — so the peak is marked on
 * the bar rather than left in a column.
 */
export function resourceLimits(record) {
  const list = (record && record.resource_limits) || [];
  if (!Array.isArray(list)) return [];

  return list
    .map((row) => {
      const limit = Number(row.limit_value);
      const current = Number(row.current_utilization);
      const peak = Number(row.max_utilization);
      const usable = Number.isFinite(limit) && limit > 0;
      const pct = usable ? (current / limit) * 100 : null;
      const peakPct = usable && Number.isFinite(peak) ? (peak / limit) * 100 : null;

      return {
        name: row.resource_name,
        current,
        peak,
        limit,
        pct,
        peakPct,
        // Judged on the peak: that is the number that will refuse a connection.
        level: usageLevel(peakPct == null ? pct : Math.max(pct ?? 0, peakPct)),
      };
    })
    .filter((r) => Number.isFinite(r.current))
    .sort((a, b) => (b.peakPct ?? b.pct ?? 0) - (a.peakPct ?? a.pct ?? 0));
}

/**
 * The memory the instance has, and what it is being spent on.
 *
 * Reported as a flat set of byte counts, but two of them are parts of a third:
 * the buffer cache and the shared pool live inside the SGA. Shown as the whole
 * and its parts rather than as five equal numbers.
 */
export function memoryBreakdown(record) {
  const memory = record && record.memory;
  if (!memory || typeof memory !== "object") return null;

  const read = (key) => {
    const n = Number(memory[key]);
    return Number.isFinite(n) && n > 0 ? n : null;
  };

  const sga = read("sga_total_bytes");
  const pgaAllocated = read("pga_allocated_bytes");
  // Each part names the whole it is a share of, because "50%" of what is the
  // only question the number raises.
  const parts = [
    { label: "Buffer cache", bytes: read("buffer_cache_bytes"), of: sga, ofLabel: "the SGA" },
    { label: "Shared pool", bytes: read("shared_pool_bytes"), of: sga, ofLabel: "the SGA" },
    {
      label: "PGA in use",
      bytes: read("pga_inuse_bytes"),
      of: pgaAllocated,
      ofLabel: "the PGA allocated",
    },
  ].filter((p) => p.bytes != null && p.of != null);

  if (sga == null && pgaAllocated == null) return null;
  return {
    sga,
    pgaAllocated,
    parts: parts.map((p) => ({ ...p, pct: (p.bytes / p.of) * 100 })),
  };
}

/** Indexes the optimiser cannot use until somebody rebuilds them. */
export function unusableIndexes(record) {
  const usage = (record && record.index_usage) || {};
  const list = usage.unusable_indexes;
  return Array.isArray(list)
    ? list.map((row) => ({
        owner: row.owner || "",
        name: row.index_name || row.name || "",
        status: row.status || "UNUSABLE",
      }))
    : [];
}

/* ───────────────────────────────────────────────────────────────
   Grouping — because forty-three cards is not a page
   ─────────────────────────────────────────────────────────────── */

/**
 * The checks, gathered by the question someone came with.
 *
 * A full Oracle reading renders forty-three cards and thirteen thousand pixels,
 * which nobody reads; they arrive asking one thing — "is it out of space?",
 * "what is slow?", "did the backup run?" — and everything else is noise until
 * they ask the next one.
 *
 * Nothing is dropped: every check belongs to a group, anything unrecognised
 * falls into the last one, and each tab carries the number of cards inside it
 * so the rest of the page is visible even while it is out of the way.
 */
export const CHECK_GROUPS = [
  {
    id: "overview",
    label: "Overview",
    checks: [
      "health_summary",
      "basic_connectivity",
      "connectivity_version",
      "issues",
      "databases",
      "tags",
      "details",
    ],
  },
  {
    id: "sessions",
    label: "Sessions",
    checks: [
      "session_summary",
      "active_connections",
      "sessions_by_user",
      "idle_sessions",
      "long_running_queries",
      "wait_events",
      "long_operations",
      "top_temp_sessions",
      // drawn as an alarm of its own when somebody is waiting; this is where
      // the card lands when the check ran and found nobody
      "locks_blocking",
      "resource_limits",
    ],
  },
  {
    id: "storage",
    label: "Storage",
    checks: [
      "top_segments",
      "table_bloat",
      "datafiles_offline",
      "fast_recovery_area",
      "database_size",
      "database_sizes",
    ],
  },
  {
    id: "performance",
    label: "Performance",
    checks: [
      "top_sql_elapsed",
      "top_sql_executions",
      "index_usage",
      "dead_tuples_vacuum",
      "wal_checkpoint",
      "redo_log_switches",
      "transaction_wraparound",
      "wraparound_risk",
      "cache_hit_ratio",
      "memory",
    ],
  },
  {
    id: "recovery",
    label: "Recovery",
    checks: [
      "rman_backups",
      "archive_log_daily",
      "replication_primary",
      "replication_delay",
      "standby_destinations",
      "alert_log_errors",
    ],
  },
  {
    id: "configuration",
    label: "Configuration",
    checks: [
      "modified_parameters",
      "user_accounts",
      "failed_scheduler_jobs",
      "invalid_objects",
      "system_resources",
    ],
  },
  // Anything this code has never seen still has a home.
  { id: "other", label: "Other", checks: [] },
];

const GROUP_OF = new Map();
CHECK_GROUPS.forEach((group) => group.checks.forEach((name) => GROUP_OF.set(name, group.id)));

/** Which tab a check belongs under. */
export function groupOf(name) {
  return GROUP_OF.get(name) || "other";
}

/**
 * The checks split into their groups, in the order each group lists them, with
 * anything the group did not name kept in the order the API sent it.
 */
export function groupChecks(checks) {
  const byGroup = new Map(CHECK_GROUPS.map((g) => [g.id, []]));

  (checks || []).forEach((entry) => {
    byGroup.get(groupOf(entry[0])).push(entry);
  });

  CHECK_GROUPS.forEach((group) => {
    const named = group.checks;
    byGroup.get(group.id).sort((a, b) => {
      const ia = named.indexOf(a[0]);
      const ib = named.indexOf(b[0]);
      // unnamed checks keep the order they arrived in, after the named ones
      return (ia === -1 ? named.length : ia) - (ib === -1 ? named.length : ib);
    });
  });

  return CHECK_GROUPS.map((group) => ({
    ...group,
    entries: byGroup.get(group.id),
  })).filter((group) => group.entries.length > 0);
}
