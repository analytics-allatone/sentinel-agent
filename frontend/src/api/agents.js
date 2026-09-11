/**
 * The registered agents, normalised once.
 *
 * `/get-agents` answers with the platform's own field names (`agent_name`,
 * `host_name`, `main_ip`); several screens want the same three facts about an
 * agent, so the mapping lives here rather than being retyped at each call site.
 *
 * Best-effort by design: a screen that only wants a hostname to caption a chart
 * should not fail because this call did. A rejected request comes back as an
 * empty list, and the caller shows what it has.
 */
import api from "./api";

/**
 * @typedef {Object} AgentSummary
 * @property {string|number} id
 * @property {string} name      agent_name — what every report keys on
 * @property {string} hostName
 * @property {string} ipAddress main_ip
 * @property {string} os
 * @property {string} status    raw platform status ("active", "disconnected", …)
 */

/**
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<AgentSummary[]>}
 */
export async function fetchAgents(options = {}) {
  try {
    const res = await api.get("/get-agents", {
      signal: options.signal,
      // callers render their own loaders; the blocking overlay would cover them
      skipGlobalLoader: true,
    });
    const list = (res.data && res.data.data && res.data.data.agents) || [];
    return list.map((a, i) => ({
      id: a.id ?? i,
      name: a.agent_name || "",
      hostName: a.host_name || "",
      ipAddress: a.main_ip || "",
      os: `${a.os || ""} ${a.release || ""}`.trim(),
      status: a.status || (a.is_active ? "active" : "disconnected"),
    }));
  } catch (err) {
    return [];
  }
}

/**
 * The entry for one agent name, or null. Names are compared case-insensitively
 * and trimmed, since they arrive from URLs and hand-typed fields.
 *
 * @param {AgentSummary[]} agents
 * @param {string} name
 * @returns {AgentSummary|null}
 */
export function findAgent(agents, name) {
  const wanted = String(name || "").trim().toLowerCase();
  if (!wanted) return null;
  return (agents || []).find((a) => a.name.trim().toLowerCase() === wanted) || null;
}

export default fetchAgents;
