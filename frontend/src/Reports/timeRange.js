/**
 * Rolling time-window helpers.
 *
 * The canonical builder is {@link lastHoursRange}: it returns a window that
 * always ends "now" and starts `hours` earlier, in ISO 8601 UTC. Everything
 * else here is a thin wrapper for a specific caller (the request payload, or the
 * dashboard's <input type="datetime-local"> fields).
 *
 * `now` is injectable on every function purely so they can be unit-tested with a
 * fixed instant; leave it out in app code and each call is dynamic.
 *
 * @typedef {Object} TimeRange
 * @property {string} from  ISO 8601 UTC (YYYY-MM-DDTHH:mm:ss.sssZ), `hours` before `to`
 * @property {string} to    ISO 8601 UTC (YYYY-MM-DDTHH:mm:ss.sssZ), the current instant
 */

const HOUR_MS = 60 * 60 * 1000;

// The dashboard shows India Standard Time (UTC+5:30, no DST); the capacity API
// still takes naive UTC. These helpers bridge the two.
const IST_OFFSET_MS = 330 * 60 * 1000;

/** A valid Date for `now`, or the current instant if the argument is unusable. */
function resolveNow(now) {
  return now instanceof Date && !Number.isNaN(now.getTime()) ? now : new Date();
}

/**
 * Build a window of the most recent `hours` hours, ending at the moment of the
 * call. `from` is always strictly before `to` because the span is forced
 * positive.
 *
 * @param {number} [hours=12] window length in hours (non-positive values fall back to 12)
 * @param {Date} [now] end of the window; defaults to the current instant
 * @returns {TimeRange}
 *
 * @example
 * lastHoursRange(); // { from: "2026-07-17T06:00:00.000Z", to: "2026-07-17T18:00:00.000Z" }
 */
export function lastHoursRange(hours = 12, now) {
  const to = resolveNow(now);
  const span = Number.isFinite(hours) && hours > 0 ? hours : 12;
  const from = new Date(to.getTime() - span * HOUR_MS);
  return { from: from.toISOString(), to: to.toISOString() };
}

/**
 * The last-12-hours window — the request-payload default.
 * @param {Date} [now]
 * @returns {TimeRange}
 */
export function lastTwelveHoursRange(now) {
  return lastHoursRange(12, now);
}

/** ISO-8601-UTC instant -> "YYYY-MM-DDTHH:mm" IST wall clock (datetime-local). */
function toIstInput(isoUtc) {
  return new Date(Date.parse(isoUtc) + IST_OFFSET_MS).toISOString().slice(0, 16);
}

/**
 * The same window as {@link lastHoursRange}, but as <input type="datetime-local">
 * values: `YYYY-MM-DDTHH:mm`, minute precision, in IST.
 *
 * IST (not local, not UTC) so the seeded inputs line up with the dashboard's IST
 * axis. The digits the user sees and edits are IST wall clock; {@link istInputToApi}
 * converts them back to the naive-UTC form the API expects.
 *
 * @param {number} [hours=12]
 * @param {Date} [now]
 * @returns {{ from: string, to: string }}
 */
export function lastHoursInputs(hours = 12, now) {
  const { from, to } = lastHoursRange(hours, now);
  return { from: toIstInput(from), to: toIstInput(to) };
}

/**
 * Convert an IST datetime-local value into the naive-UTC timestamp the capacity
 * API expects, appending seconds.
 *
 * The digits of `local` are an IST wall clock; the API wants the same *instant*
 * as a naive (zoneless) UTC string, so we read the digits as UTC-labelled, then
 * subtract the IST offset.
 *
 * @param {string} local    "YYYY-MM-DDTHH:mm" understood as IST
 * @param {string} seconds  "00" for the window start, "59" for the end
 * @returns {string} "YYYY-MM-DDTHH:mm:ss" in UTC, no zone
 *
 * @example
 * istInputToApi("2026-07-17T23:30", "00"); // "2026-07-17T18:00:00"  (23:30 IST = 18:00 UTC)
 */
export function istInputToApi(local, seconds) {
  // datetime-local is always "" or exactly this shape; Date.parse is too lenient
  // to trust with anything else (it reads "garbage" as a year-2000 date).
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(local)) return "";
  const istLabelledMs = Date.parse(`${local}:${seconds}Z`); // read the digits as if UTC
  if (Number.isNaN(istLabelledMs)) return "";
  return new Date(istLabelledMs - IST_OFFSET_MS).toISOString().slice(0, 19);
}
