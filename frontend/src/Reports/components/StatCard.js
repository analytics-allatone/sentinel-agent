import React from "react";
import "./StatCard.css";

/**
 * props:
 *  - label   : small caption above the value
 *  - value   : the big number/text
 *  - sub     : small text below the value (e.g. "needs review")
 *  - subColor: "danger" | "warning" | "success" | "muted"
 *  - loading : render a skeleton instead of content
 *
 * The status subColors carry a dot alongside the text, so state is never
 * signalled by colour alone.
 */
export default function StatCard({ label, value, sub, subColor = "muted", loading = false }) {
  if (loading) {
    return (
      <div className="stat-card">
        <div className="stat-skel stat-skel-label" />
        <div className="stat-skel stat-skel-value" />
        <div className="stat-skel stat-skel-sub" />
      </div>
    );
  }

  const hasSub = sub != null && sub !== "";

  return (
    <div className={`stat-card stat-card-${subColor}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value == null || value === "" ? "—" : value}</div>
      {hasSub && (
        <div className={`stat-sub stat-sub-${subColor}`}>
          {subColor !== "muted" && <span className="stat-dot" aria-hidden="true" />}
          <span className="stat-sub-text">{sub}</span>
        </div>
      )}
    </div>
  );
}
