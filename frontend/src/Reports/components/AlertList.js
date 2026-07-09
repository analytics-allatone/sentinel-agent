import React from "react";

/**
 * props:
 *  - alerts : [{ priority: "critical"|"warning"|"resolved", description, agent_name }]
 *
 * Numbered list, colour-coded left border + background tint per priority,
 * with the affected agent shown as a small pill tag.
 */
export default function AlertList({ alerts = [] }) {
  if (alerts.length === 0) {
    return <div className="cap-empty-row">No capacity alerts for this period.</div>;
  }

  return (
    <ol className="cap-alerts">
      {alerts.map((a, i) => (
        <li key={a.id ?? i} className={`cap-alert cap-alert-${a.priority || "warning"}`}>
          <span className="cap-alert-num">{String(i + 1).padStart(2, "0")}</span>
          <span className="cap-alert-body">
            <span className="cap-alert-desc">{a.description}</span>
            {a.agent_name && <span className="cap-alert-tag">{a.agent_name}</span>}
          </span>
        </li>
      ))}
    </ol>
  );
}
