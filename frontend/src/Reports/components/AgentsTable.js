import React from "react";

/**
 * props:
 *  - agents: [{ name, hostname, os, last_seen, status }]
 *            status: "online" | "degraded" | "offline"
 *  - loading
 */
const DOT = {
  online: "#5a9216",
  degraded: "#e08b0a",
  offline: "#d64545",
};

const BADGE_CLASS = {
  online: "agent-badge-online",
  degraded: "agent-badge-degraded",
  offline: "agent-badge-offline",
};

export default function AgentsTable({ agents = [], loading = false }) {
  if (loading) {
    return (
      <div className="agents-list">
        {[0, 1, 2, 3].map((i) => (
          <div className="agent-row" key={i}>
            <div className="stat-skel" style={{ height: 14, width: "100%" }} />
          </div>
        ))}
      </div>
    );
  }

  if (agents.length === 0) {
    return <div className="evt-empty">No agents registered.</div>;
  }

  return (
    <div className="agents-list">
      {agents.map((a, i) => (
        <div className="agent-row" key={a.id ?? i}>
          <span className="agent-dot" style={{ background: DOT[a.status] || "#999" }} />
          <span className="agent-name">{a.name}</span>
          <span className="agent-meta">
            {a.hostname} — {a.os} — last seen {a.last_seen}
          </span>
          <span className={`agent-badge ${BADGE_CLASS[a.status] || ""}`}>{a.status}</span>
        </div>
      ))}
    </div>
  );
}
