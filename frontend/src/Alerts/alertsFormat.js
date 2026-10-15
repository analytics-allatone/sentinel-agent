/**
 * Detections from GET /get-alerts.
 *
 * The endpoint answers a quarter of a million rows fifty at a time, which
 * shapes everything here: nothing in this file may claim to describe the whole
 * set from one page of it. Figures that are true of everything — the totals per
 * severity — come from the server's own `total`; figures that are only true of
 * the rows on screen say so where they are shown.
 */

/**
 * The ladder the API counts on, highest first.
 *
 * `severity` is the number and `severity_label` the word; both arrive, and they
 * agree, but the number is what `severity` and `severity_min` filter on.
 */
export const SEVERITIES = [
  { level: 5, label: "critical", tone: "critical" },
  { level: 4, label: "high", tone: "high" },
  { level: 3, label: "medium", tone: "medium" },
  { level: 2, label: "low", tone: "low" },
  { level: 1, label: "info", tone: "info" },
];

/**
 * Picking a level asks one of two different questions.
 *
 * "High and above" is the triage question and what the chips did from the
 * start; "exactly high" is the one you ask when counting, or when a level
 * below has drowned out the one you are looking at. They are different
 * parameters — severity_min and severity — so the page says which it is
 * sending rather than guessing.
 */
export const SEVERITY_MODES = [
  { id: "min", label: "and above", param: "severity_min" },
  { id: "exact", label: "exactly", param: "severity" },
];

/** The categories the endpoint documents. */
export const CATEGORIES = [
  "file",
  "process",
  "network",
  "authentication",
  "usb",
  "database",
];

const BY_LEVEL = new Map(SEVERITIES.map((s) => [s.level, s]));

/** The word for a level, falling back to whatever the row itself said. */
export function severityOf(alert) {
  const known = BY_LEVEL.get(Number(alert && alert.severity));
  if (known) return known;
  return {
    level: Number(alert && alert.severity) || 0,
    label: (alert && alert.severity_label) || "unknown",
    tone: "unknown",
  };
}

/** The envelope's payload, however the caller got hold of it. */
export function readAlerts(payload) {
  const data = (payload && payload.data) || payload || {};
  return {
    total: Number(data.total) || 0,
    page: Number(data.page) || 1,
    pageSize: Number(data.page_size) || 0,
    alerts: Array.isArray(data.alerts) ? data.alerts : [],
  };
}

/** How many pages there are to walk, at this size. */
export function pageCount(total, pageSize) {
  const size = Number(pageSize);
  if (!Number.isFinite(size) || size <= 0) return 0;
  return Math.ceil((Number(total) || 0) / size);
}

/**
 * "4 min ago".
 *
 * Detections are read newest-first and what matters is how long ago, not the
 * wall-clock instant — which is kept in the title for when it does.
 */
export function relativeTime(value, now = Date.now()) {
  const then = Date.parse(value);
  if (Number.isNaN(then)) return "—";

  const seconds = Math.round((now - then) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 45) return "just now";
  if (seconds < 90) return "1 min ago";

  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;

  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hr${hours === 1 ? "" : "s"} ago`;

  const days = Math.round(hours / 24);
  if (days < 30) return `${days} day${days === 1 ? "" : "s"} ago`;

  const months = Math.round(days / 30);
  if (months < 12) return `${months} month${months === 1 ? "" : "s"} ago`;
  return `${Math.round(months / 12)} yr ago`;
}

/** The instant in full, for the tooltip the relative time hides. */
export function exactTime(value) {
  const then = Date.parse(value);
  if (Number.isNaN(then)) return "";
  return new Date(then).toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/**
 * How long the burst behind one alert lasted.
 *
 * An alert is a run of events, not one: `event_count` of them between
 * `first_seen` and `last_seen`. "9 events over 42s" is a different thing from
 * "9 events at once", and only the pair of timestamps tells them apart.
 */
export function burstSpan(alert) {
  const from = Date.parse(alert && alert.first_seen);
  const to = Date.parse(alert && alert.last_seen);
  if (Number.isNaN(from) || Number.isNaN(to)) return "";

  const seconds = Math.max(0, Math.round((to - from) / 1000));
  if (seconds === 0) return "at once";
  if (seconds < 60) return `over ${seconds}s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `over ${minutes} min`;
  return `over ${Math.round(minutes / 60)} hr`;
}

/**
 * "attack.t1567.002" -> "T1567.002", and where to read about it.
 *
 * Some rows carry an empty technique, which is not the same as a technique
 * named "" — those get nothing rather than a dead link.
 */
export function technique(value) {
  const raw = String(value || "").trim();
  const match = raw.match(/t(\d{4})(?:\.(\d{3}))?/i);
  if (!match) return null;

  const id = match[2] ? `T${match[1]}.${match[2]}` : `T${match[1]}`;
  const path = match[2] ? `${match[1]}/${match[2]}` : match[1];
  return { id, url: `https://attack.mitre.org/techniques/T${path}/` };
}

/** The rule id without the engine's prefix: SIGMA_34986307-… -> 34986307-… */
export function ruleId(value) {
  return String(value || "").replace(/^[A-Z]+_/, "");
}

/**
 * The same detection, over and over, folded into one row.
 *
 * Grouping can only ever cover the rows in hand — the next page holds more of
 * the same rule — so this is offered as a way to read one page, and the page
 * says as much where the toggle is.
 */
export function groupByRule(alerts) {
  const groups = new Map();

  (alerts || []).forEach((alert) => {
    const key = `${alert.rule_id}|${alert.detail}`;
    const existing = groups.get(key);

    if (!existing) {
      groups.set(key, {
        key,
        rule_id: alert.rule_id,
        detail: alert.detail,
        technique: alert.technique,
        category: alert.category,
        severity: alert.severity,
        severity_label: alert.severity_label,
        alerts: 1,
        events: Number(alert.event_count) || 0,
        agents: new Set([alert.agent_name]),
        entities: new Set([alert.entity]),
        first_seen: alert.first_seen,
        last_seen: alert.last_seen,
      });
      return;
    }

    existing.alerts += 1;
    existing.events += Number(alert.event_count) || 0;
    existing.agents.add(alert.agent_name);
    existing.entities.add(alert.entity);
    // the window the group covers, not the window of whichever row came first
    if (Date.parse(alert.first_seen) < Date.parse(existing.first_seen)) {
      existing.first_seen = alert.first_seen;
    }
    if (Date.parse(alert.last_seen) > Date.parse(existing.last_seen)) {
      existing.last_seen = alert.last_seen;
    }
  });

  return [...groups.values()]
    .map((group) => ({
      ...group,
      agents: [...group.agents].filter(Boolean),
      entities: [...group.entities].filter(Boolean),
    }))
    .sort(
      (a, b) =>
        b.severity - a.severity ||
        b.alerts - a.alerts ||
        Date.parse(b.last_seen) - Date.parse(a.last_seen)
    );
}

/**
 * The time windows worth one click.
 *
 * Both ends are computed when the window is applied rather than stored, so a
 * page left open overnight does not keep asking about yesterday's "last hour".
 * Every request carries a window — there is no "everything" option, because at
 * a quarter of a million rows "everything" is not a view anyone can read. The
 * custom range is the way back further than thirty days.
 */
export const TIME_RANGES = [
  { id: "1h", label: "Last 1 hour", hours: 1 },
  { id: "3h", label: "Last 3 hours", hours: 3 },
  { id: "6h", label: "Last 6 hours", hours: 6 },
  { id: "12h", label: "Last 12 hours", hours: 12 },
  { id: "24h", label: "Last 24 hours", hours: 24 },
  { id: "5d", label: "Last 5 days", hours: 24 * 5 },
  { id: "10d", label: "Last 10 days", hours: 24 * 10 },
  { id: "15d", label: "Last 15 days", hours: 24 * 15 },
  { id: "30d", label: "Last 30 days", hours: 24 * 30 },
];

/** What the page asks for before anyone has chosen. */
export const DEFAULT_RANGE = "24h";

/** The id meaning "I will give you the two ends myself". */
export const CUSTOM_RANGE = "custom";

/** A preset's two ends, as the instants the API wants. */
export function rangeWindow(id, now = Date.now()) {
  const range = TIME_RANGES.find((r) => r.id === id);
  if (!range) return null;
  return {
    from_dt: new Date(now - range.hours * 3600 * 1000).toISOString(),
    to_dt: new Date(now).toISOString(),
  };
}

/** The start alone, for callers that only need the lower bound. */
export function rangeStart(id, now = Date.now()) {
  const window = rangeWindow(id, now);
  return window ? window.from_dt : null;
}

/**
 * A `datetime-local` value is wall-clock time with no zone, which is exactly
 * how someone reads a clock — so it is interpreted in their zone and converted,
 * rather than being passed through as though it were already UTC.
 */
export function localToIso(value) {
  if (!value) return null;
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? null : at.toISOString();
}

/** The reverse, to seed the custom fields from whatever is in force. */
export function isoToLocalInput(value) {
  const at = Date.parse(value);
  if (Number.isNaN(at)) return "";
  const local = new Date(at - new Date(at).getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}

/**
 * Why a hand-typed window cannot be used, or nothing if it can.
 *
 * Said before the request rather than after: the endpoint answers an inverted
 * range with an empty list, which reads as "no alerts" when it means "those
 * dates are the wrong way round".
 */
export function rangeProblem(fromLocal, toLocal) {
  if (!fromLocal || !toLocal) return "Both a start and an end are needed.";
  const from = localToIso(fromLocal);
  const to = localToIso(toLocal);
  if (!from || !to) return "That is not a date and time.";
  if (Date.parse(from) >= Date.parse(to)) return "The start has to come before the end.";
  return "";
}

/** The window in words, for the line that says what is being shown. */
export function describeWindow(window) {
  if (!window || !window.from_dt || !window.to_dt) return "";
  const shown = (value) =>
    new Date(value).toLocaleString(undefined, {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
    });
  return `${shown(window.from_dt)} → ${shown(window.to_dt)}`;
}

/** 246201 -> "246,201", and nothing at all for a figure that never arrived. */
export function count(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString() : "—";
}

/* ───────────────────────────────────────────────────────────────
   Paging — two numbers, and only ever numbers
   ─────────────────────────────────────────────────────────────── */

/** The endpoint's own bounds: anything outside these comes back 422. */
export const PAGE_SIZE_MIN = 1;
export const PAGE_SIZE_MAX = 200;
export const DEFAULT_PAGE_SIZE = 50;

/**
 * What a numeric field is allowed to hold while it is being typed.
 *
 * `type="number"` is not the guard it looks like: Chrome accepts "e", "+" and
 * "-" inside one and then reports `value` as the empty string, so a field that
 * looks like it holds 5e3 hands over nothing at all. Digits are kept and
 * everything else is dropped as it is typed, which also leaves "" available as
 * the legitimate half-typed state.
 */
export function digitsOnly(text) {
  return String(text == null ? "" : text).replace(/[^0-9]/g, "");
}

/**
 * The number that will actually be sent.
 *
 * Clamped rather than rejected: someone who types 900 into a field whose
 * endpoint stops at 200 meant "as many as I can have", and a 422 is a worse
 * answer than 200 rows. An empty or unreadable field falls back.
 */
export function clampNumber(value, { min, max, fallback }) {
  const n = Number(digitsOnly(value));
  if (!Number.isFinite(n) || n < min) return fallback !== undefined ? fallback : min;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

/** The page size a request may carry. */
export function safePageSize(value) {
  return clampNumber(value, {
    min: PAGE_SIZE_MIN,
    max: PAGE_SIZE_MAX,
    fallback: DEFAULT_PAGE_SIZE,
  });
}

/** The page number a request may carry, never past the last one there is. */
export function safePage(value, pages) {
  const last = Number.isFinite(Number(pages)) && Number(pages) > 0 ? Number(pages) : 1;
  return clampNumber(value, { min: 1, max: last, fallback: 1 });
}

/**
 * Narrow the rows already on screen.
 *
 * Not the same thing as the filters above it, and the page says so: those ask
 * the server a new question, this one only hides rows out of the fifty already
 * fetched. Useful for "where is that one agent in this page", useless for
 * "show me every alert for that agent" — which is what the agent filter is for.
 *
 * Every field a reader can see is searched, so what they type matches what
 * they are looking at.
 */
export function filterRows(rows, needle) {
  const wanted = String(needle || "").trim().toLowerCase();
  if (!wanted) return rows || [];

  return (rows || []).filter((row) => {
    const haystack = [
      row.detail,
      row.category,
      row.agent_name,
      row.entity,
      row.technique,
      row.severity_label,
      ruleId(row.rule_id),
      // the folded rows carry lists instead of single values
      Array.isArray(row.agents) ? row.agents.join(" ") : "",
      Array.isArray(row.entities) ? row.entities.join(" ") : "",
    ];
    return haystack.some((field) => String(field || "").toLowerCase().includes(wanted));
  });
}

/* ───────────────────────────────────────────────────────────────
   The view, in the address bar
   ─────────────────────────────────────────────────────────────── */

/**
 * The filters as query parameters, and back again.
 *
 * Without this a view cannot be sent to anyone: "the high-severity alerts on
 * shiv1 in the last hour" is six clicks to describe and one link to share, and
 * a refresh threw all six away. Only what differs from the default is written,
 * so an untouched page keeps a clean address.
 */
export function viewToParams({ severity, severityMode, applied }) {
  const params = {};
  if (severity) {
    params.sev = String(severity);
    // the mode only means anything when a level is chosen
    if (severityMode === "exact") params.mode = "exact";
  }
  if (applied.agent && applied.agent.trim()) params.agent = applied.agent.trim();
  if (applied.category) params.category = applied.category;
  if (applied.range && applied.range !== DEFAULT_RANGE) params.range = applied.range;
  if (applied.range === CUSTOM_RANGE && applied.customWindow) {
    params.from = applied.customWindow.from_dt;
    params.to = applied.customWindow.to_dt;
  }
  if (applied.pageSize !== DEFAULT_PAGE_SIZE) params.size = String(applied.pageSize);
  return params;
}

/**
 * A view read back out of the address bar.
 *
 * Everything is clamped and checked against what the endpoint accepts: a URL
 * is typed, pasted and edited by hand, and a page that trusts it sends
 * nonsense to the server and shows an error the reader cannot act on.
 */
export function paramsToView(search) {
  const get = (key) => {
    const value = search instanceof URLSearchParams ? search.get(key) : (search || {})[key];
    return value == null ? "" : String(value);
  };

  const level = Number(get("sev"));
  const known = SEVERITIES.some((s) => s.level === level);
  const range = get("range");
  const custom = range === CUSTOM_RANGE;
  const from = get("from");
  const to = get("to");
  const usableWindow = custom && !Number.isNaN(Date.parse(from)) && !Number.isNaN(Date.parse(to));

  return {
    severity: known ? level : 0,
    severityMode: get("mode") === "exact" ? "exact" : "min",
    applied: {
      agent: get("agent"),
      category: CATEGORIES.includes(get("category")) ? get("category") : "",
      // a range nobody offers falls back rather than asking for nothing
      range:
        custom || TIME_RANGES.some((r) => r.id === range) ? range || DEFAULT_RANGE : DEFAULT_RANGE,
      customWindow: usableWindow ? { from_dt: from, to_dt: to } : null,
      pageSize: get("size") ? safePageSize(get("size")) : DEFAULT_PAGE_SIZE,
    },
    page: Math.max(1, clampNumber(get("page"), { min: 1, max: 1e9, fallback: 1 })),
  };
}

/** Rows as a CSV, with the columns a reader can see on screen. */
export function alertsToCsv(rows) {
  const columns = [
    ["id", (r) => r.id],
    ["severity", (r) => r.severity_label || r.severity],
    ["category", (r) => r.category],
    ["detail", (r) => r.detail],
    ["technique", (r) => (technique(r.technique) || {}).id || ""],
    ["agent", (r) => r.agent_name],
    ["entity", (r) => r.entity],
    ["events", (r) => r.event_count],
    ["first_seen", (r) => r.first_seen],
    ["last_seen", (r) => r.last_seen],
    ["rule_id", (r) => ruleId(r.rule_id)],
  ];

  // RFC 4180: quote everything and double the quotes inside, so a detail with
  // a comma in it cannot shift every column after it.
  const cell = (value) => `"${String(value == null ? "" : value).replace(/"/g, '""')}"`;

  return [
    columns.map(([name]) => cell(name)).join(","),
    ...(rows || []).map((row) => columns.map(([, read]) => cell(read(row))).join(",")),
  ].join("\r\n");
}

/** What to call the file, so a folder of them stays sortable. */
export function csvFilename(now = new Date()) {
  const stamp = new Date(now).toISOString().slice(0, 19).replace(/[:T]/g, "-");
  return `alerts-${stamp}.csv`;
}
