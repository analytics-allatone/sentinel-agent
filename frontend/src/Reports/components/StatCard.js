import React from "react";
import "./StatCard.css";

/**
 * props:
 *  - label   : small caption above the value
 *  - value   : the big number/text
 *  - sub     : small text below the value (e.g. "needs review")
 *  - subColor: "danger" | "warning" | "success" | "muted"
 *  - loading : render a skeleton instead of content
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

  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub != null && sub !== "" && (
        <div className={`stat-sub stat-sub-${subColor}`}>{sub}</div>
      )}
    </div>
  );
}
