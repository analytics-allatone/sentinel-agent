/**
 * Capacity-monitoring overview endpoint.
 *
 * Plain JavaScript — the shapes below are documented with JSDoc typedefs so
 * editors still offer autocomplete without any TypeScript in the project.
 *
 * @typedef {Object} Point
 * @property {string} t      ISO-8601, UTC with a +00:00 offset and microseconds,
 *                           e.g. "2026-07-15T11:23:22.432392+00:00"
 * @property {number} value
 *
 * @typedef {Object} Summary
 * @property {number} avg_cpu_percent        percent
 * @property {number} avg_memory             MEGABYTES — not a percent. Never share an
 *                                           axis with memory_utilization_series, whose
 *                                           values are percentages.
 * @property {number} avg_agent_cpu_percent  percent
 * @property {number} avg_agent_memory       percent
 * @property {number} avg_bandwidth_mbps     Mbps — the mean of agent_bandwidth_mbps_series
 *
 * @typedef {Object} Overview
 * @property {string} agent_name
 * @property {string} from                   naive ISO, echoed back
 * @property {string} to                     naive ISO, echoed back
 * @property {number} sample_count
 * @property {Summary} summary
 * @property {Point[]} cpu_utilization_series           percent
 * @property {Point[]} memory_utilization_series        percent
 * @property {Point[]} storage_utilization_series       percent
 * @property {Point[]} agent_cpu_utilization_series     percent
 * @property {Point[]} agent_memory_utilization_series  percent
 * @property {Point[]} agent_bandwidth_mbps_series      MEGABITS PER SECOND — the only
 *                                                      non-percent series. Charted on its
 *                                                      own pane; it must never share a
 *                                                      0-100 axis with the ones above.
 *
 * @typedef {Object} OverviewParams
 * @property {string} agentName
 * @property {string} fromDt  naive ISO, no timezone, e.g. "2026-07-14T00:00:00"
 * @property {string} toDt    naive ISO, no timezone, e.g. "2026-07-15T23:59:59"
 */

import api from "../api/api";

export const OVERVIEW_PATH = "/api/v1/capacity-monitoring/overview";

/**
 * camelCase params -> the wire query object the endpoint expects.
 *
 * This is the ONLY place the snake_case names are produced. Both the request
 * and the URL reported on failure go through it, so the two cannot drift apart.
 *
 * @param {OverviewParams} params
 */
function toQuery(params) {
  const p = params || {};
  return {
    agent_name: p.agentName ?? "",
    from_dt: p.fromDt ?? "",
    to_dt: p.toDt ?? "",
  };
}

/**
 * Wire query object -> query string.
 *
 * URLSearchParams percent-encodes the colons in the timestamps
 * (T00%3A00%3A00), which is what the endpoint's contract asks for; axios'
 * default serializer un-escapes them, so it is replaced with this.
 *
 * Takes the already-snake_cased object — axios hands the serializer whatever
 * was passed as `params`, so this must read those exact keys.
 *
 * @param {{agent_name: string, from_dt: string, to_dt: string}} query
 */
function serializeQuery(query) {
  return new URLSearchParams(query).toString();
}

/**
 * Path + query, relative to the API base.
 * @param {OverviewParams} params
 */
export function overviewUrl(params) {
  return `${OVERVIEW_PATH}?${serializeQuery(toQuery(params))}`;
}

/**
 * The full URL, for showing the user exactly what failed.
 * @param {OverviewParams} params
 */
export function absoluteOverviewUrl(params) {
  const base = (api.defaults && api.defaults.baseURL) || "";
  return `${base}${overviewUrl(params)}`;
}

/** Error carrying the bits the error state needs to render. */
function capacityError(message, { status, url, cause }) {
  const err = new Error(message);
  err.name = "CapacityApiError";
  err.status = status;
  err.url = url;
  err.cause = cause;
  return err;
}

function messageForStatus(status, detail) {
  if (detail) return detail;
  if (status === 401 || status === 403) return "Session expired. Sign in again, then retry.";
  if (status === 404) return "The agent name did not match any registered agent.";
  if (status === 422) return "The API rejected the range. Check that From is before To.";
  if (status >= 500) return "The capacity service failed to answer. Retry, or try a shorter range.";
  return "The request failed.";
}

/**
 * Fetch one overview window.
 *
 * Goes through the project's shared axios client so the auth interceptor
 * attaches the bearer token.
 *
 * @param {OverviewParams} params
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<Overview>}
 */
export async function fetchOverview(params, options = {}) {
  const url = absoluteOverviewUrl(params);
  try {
    const res = await api.get(OVERVIEW_PATH, {
      params: toQuery(params),
      paramsSerializer: { serialize: serializeQuery },
      signal: options.signal,
    });
    return res.data.data || {};
  } catch (cause) {
    if (cause && (cause.code === "ERR_CANCELED" || cause.name === "CanceledError")) throw cause;

    const status = cause && cause.response ? cause.response.status : 0;
    const detail = cause && cause.response && cause.response.data && cause.response.data.detail;
    const message = status
      ? messageForStatus(status, typeof detail === "string" ? detail : "")
      : "No response from the API. Check the network and that the service is up.";

    throw capacityError(message, { status, url, cause });
  }
}
