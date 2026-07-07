import React from "react";

/**
 * props:
 *  - events  : [{ severity, message, category, timestamp }]
 *  - maxItems: cap number rendered (default 5)
 */
const DOT_COLORS = {
  critical: "#d64545",
  high: "#e08b0a",
  medium: "#2b7fd0",
  low: "#5a9216",
};

export default function EventList({ events = [], maxItems = 5 }) {
  const items = events.slice(0, maxItems);

  if (items.length === 0) {
    return <div className="evt-empty">No events for this period.</div>;
  }

  return (
    <ul className="evt-list">
      {items.map((e, i) => (
        <li className="evt-item" key={i}>
          <span
            className="evt-dot"
            style={{ background: DOT_COLORS[e.severity] || "#999" }}
          />
          <span className="evt-msg">{e.message}</span>
          {e.category && (
            <span className={`sev-badge cat-badge cat-${e.category}`}>{e.category}</span>
          )}
          <span className="evt-time">{e.timestamp}</span>
        </li>
      ))}
    </ul>
  );
}
