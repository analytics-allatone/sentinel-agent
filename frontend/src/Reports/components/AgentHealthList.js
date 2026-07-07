import React from "react";

/**
 * props:
 *  - agents : [{ agent_name, hostname, status, last_seen }]
 *
 * Renders: status dot + name — hostname + last seen + status badge.
 */
const DOT = {
  online: "#5a9216",
  degraded: "#e08b0a",
  offline: "#d64545",
};

const BADGE = {
  online: "cap-badge-online",
  degraded: "cap-badge-degraded",
  offline: "cap-badge-offline",
};

export default function AgentHealthList({ agents = [] }) {
  if (agents.length === 0) {
    return <div className="cap-empty-row">No agents registered.</div>;
  }

  return (
    <div className="cap-health-list">
      {agents.map((a, i) => (
        <div className="cap-health-row" key={a.id ?? i}>
          <span className="cap-dot" style={{ background: DOT[a.status] || "#999" }} />
          <span className="cap-health-name">
            {a.agent_name} <span className="cap-health-host">— {a.hostname}</span>
          </span>
          <span className={`cap-badge ${BADGE[a.status] || ""}`}>{a.status}</span>
          <span className="cap-health-seen">{a.last_seen}</span>
        </div>
      ))}
    </div>
  );
}
