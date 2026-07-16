/**
 * Pure data utilities for the capacity dashboard.
 *
 * No React and no network in here — every export is a plain function of its
 * arguments, so this file can be unit-tested on its own.
 *
 * Times are formatted in UTC on purpose. The API returns every sample stamped
 * "+00:00", and from_dt / to_dt go out naive (no zone), so rendering in UTC is
 * the only way the axis agrees with what the user typed into the range inputs.
 */

/**
 * Payload series key -> the row field it fills.
 *
 * Every field here is a percentage EXCEPT `bw`, which is Mbps. That one is
 * charted on its own pane; putting it on a 0-100 axis would misstate it.
 */
const SERIES_FIELDS = [
  ["cpu_utilization_series", "cpu"],
  ["memory_utilization_series", "mem"],
  ["storage_utilization_series", "sto"],
  ["agent_cpu_utilization_series", "acpu"],
  ["agent_memory_utilization_series", "amem"],
  ["agent_bandwidth_mbps_series", "bw"],
];

/** A delta larger than this multiple of the median cadence counts as a hole. */
const GAP_FACTOR = 8;

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function pad(n) {
  return String(n).padStart(2, "0");
}

/**
 * Join all five series on their timestamp.
 *
 * The series are not index-aligned and do not share a length, so the union of
 * every `t` is collected and each value is written into its own field. A sample
 * a series does not have stays null — never 0, never forward-filled — so the
 * charts can render a hole as a hole.
 *
 * @param {import("./capacityApi").Overview} payload
 * @returns {Array<{i:number,t:string,ms:number,cpu:number|null,mem:number|null,sto:number|null,acpu:number|null,amem:number|null,bw:number|null}>}
 */
export function buildRows(payload) {
  const p = payload || {};
  const byMs = new Map();

  SERIES_FIELDS.forEach(([seriesKey, field]) => {
    const series = Array.isArray(p[seriesKey]) ? p[seriesKey] : [];
    series.forEach((point) => {
      if (!point || point.t == null) return;
      const ms = Date.parse(point.t);
      if (Number.isNaN(ms)) return;

      let row = byMs.get(ms);
      if (!row) {
        row = { i: 0, t: point.t, ms, cpu: null, mem: null, sto: null, acpu: null, amem: null, bw: null };
        byMs.set(ms, row);
      }
      const value = Number(point.value);
      row[field] = Number.isFinite(value) ? value : null;
    });
  });

  const rows = Array.from(byMs.values()).sort((a, b) => a.ms - b.ms);
  for (let i = 0; i < rows.length; i++) rows[i].i = i;
  return rows;
}

function median(values) {
  if (!values.length) return 0;
  const sorted = values.slice().sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

/**
 * Locate the reporting holes.
 *
 * Sampling is irregular by nature (10-13s, sometimes 20s or 35s), so a gap is
 * defined relative to the run's own median cadence rather than a fixed number
 * of seconds.
 *
 * @param {ReturnType<typeof buildRows>} rows
 * @returns {Array<{at:number, ms:number}>} `at` sits between two rows (i - 0.5)
 */
export function findGaps(rows) {
  if (!Array.isArray(rows) || rows.length < 3) return [];

  const deltas = [];
  for (let i = 1; i < rows.length; i++) deltas.push(rows[i].ms - rows[i - 1].ms);

  const cadence = median(deltas);
  if (!cadence) return [];

  const gaps = [];
  for (let i = 1; i < rows.length; i++) {
    const delta = rows[i].ms - rows[i - 1].ms;
    if (delta > GAP_FACTOR * cadence) gaps.push({ at: i - 0.5, ms: delta });
  }
  return gaps;
}

/** Epoch ms -> "17:14" (24h, UTC). */
export function formatClock(ms) {
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms);
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

/** Epoch ms -> "Jul 15, 17:14:34" (UTC). */
export function formatFull(ms) {
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms);
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}, ${pad(d.getUTCHours())}:${pad(
    d.getUTCMinutes()
  )}:${pad(d.getUTCSeconds())}`;
}

/**
 * Keep a zoom window inside [0, lastIndex].
 *
 * At an edge the window SHIFTS rather than squashing, so panning into the start
 * or end of the run never inverts or collapses the range. Indices are rounded
 * because rows are discrete samples.
 *
 * @param {number} start
 * @param {number} end
 * @param {number} lastIndex
 * @param {number} [minSpan] never zoom tighter than this many samples
 * @returns {[number, number]}
 */
export function clampRange(start, end, lastIndex, minSpan = 8) {
  if (!Number.isFinite(lastIndex) || lastIndex <= 0) return [0, 0];

  let s = Number.isFinite(start) ? start : 0;
  let e = Number.isFinite(end) ? end : lastIndex;
  if (e < s) [s, e] = [e, s];

  const span = Math.min(minSpan, lastIndex);
  if (e - s < span) {
    const centre = (s + e) / 2;
    s = centre - span / 2;
    e = centre + span / 2;
  }
  if (e - s > lastIndex) {
    s = 0;
    e = lastIndex;
  }
  if (s < 0) {
    e += -s;
    s = 0;
  }
  if (e > lastIndex) {
    s -= e - lastIndex;
    e = lastIndex;
  }
  return [Math.max(0, Math.round(s)), Math.min(lastIndex, Math.round(e))];
}

/** Duration in ms -> "5h 12m" / "45m" / "35s". */
export function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "";
  const totalSeconds = Math.round(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${seconds}s`;
}
