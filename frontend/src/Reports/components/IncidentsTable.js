import React, { useMemo, useState } from "react";

/**
 * props:
 *  - incidents: [{ date, severity, category, description, agent_name, mitre_technique }]
 *  - loading
 *
 * Click a column header to sort by it. Default sort: date descending.
 */
const COLUMNS = [
  { key: "date", label: "Date" },
  { key: "severity", label: "Severity" },
  { key: "category", label: "Category" },
  { key: "description", label: "Description" },
  { key: "agent_name", label: "Agent" },
  { key: "mitre_technique", label: "MITRE" },
];

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

export default function IncidentsTable({ incidents = [], loading = false }) {
  const [sortKey, setSortKey] = useState("date");
  const [sortDir, setSortDir] = useState("desc"); // default: date descending

  const sorted = useMemo(() => {
    const copy = [...incidents];
    copy.sort((a, b) => {
      let av = a[sortKey];
      let bv = b[sortKey];

      if (sortKey === "severity") {
        av = SEVERITY_RANK[av] || 0;
        bv = SEVERITY_RANK[bv] || 0;
      } else if (sortKey === "date") {
        av = new Date(av).getTime() || 0;
        bv = new Date(bv).getTime() || 0;
      } else {
        av = (av || "").toString().toLowerCase();
        bv = (bv || "").toString().toLowerCase();
      }

      if (av < bv) return sortDir === "asc" ? -1 : 1;
      if (av > bv) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return copy;
  }, [incidents, sortKey, sortDir]);

  const handleSort = (key) => {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "date" ? "desc" : "asc");
    }
  };

  if (loading) {
    return (
      <div className="inc-table-wrap">
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} className="stat-skel" style={{ height: 16, margin: "8px 0" }} />
        ))}
      </div>
    );
  }

  if (incidents.length === 0) {
    return <div className="evt-empty">No incidents for this period.</div>;
  }

  return (
    <div className="inc-table-wrap">
      <table className="inc-table">
        <thead>
          <tr>
            {COLUMNS.map((c) => (
              <th
                key={c.key}
                onClick={() => handleSort(c.key)}
                className={sortKey === c.key ? "sorted" : ""}
              >
                {c.label}
                <span className="sort-caret">
                  {sortKey === c.key ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((inc, i) => (
            <tr key={i}>
              <td>{inc.date}</td>
              <td>
                <span className={`sev-badge sev-${inc.severity}`}>{inc.severity}</span>
              </td>
              <td>{inc.category}</td>
              <td>{inc.description}</td>
              <td>{inc.agent_name}</td>
              <td className="mitre-cell">{inc.mitre_technique}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
