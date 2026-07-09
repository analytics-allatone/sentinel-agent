import React, { useMemo, useState } from "react";

/**
 * props:
 *  - agents  : [{ status, agent_name, hostname, os, cpu, memory, disk, last_seen }]
 *  - loading
 *
 * Sortable columns. Default sort: status order (online > degraded > offline).
 * Null metric values render as an em dash. Metric text is colour-coded, and the
 * last-seen column is coloured by recency.
 */
const COLUMNS = [
  { key: "status", label: "", numeric: false, dot: true },
  { key: "agent_name", label: "Agent", numeric: false },
  { key: "hostname", label: "Hostname", numeric: false },
  { key: "os", label: "OS", numeric: false },
  { key: "cpu", label: "CPU", numeric: true },
  { key: "memory", label: "Memory", numeric: true },
  { key: "disk", label: "Disk", numeric: true },
  { key: "last_seen", label: "Last seen", numeric: false },
  { key: "status", label: "Status", numeric: false, badge: true },
];

const STATUS_ORDER = { online: 0, degraded: 1, offline: 2 };

const BADGE = {
  online: "cap-badge-online",
  degraded: "cap-badge-degraded",
  offline: "cap-badge-offline",
};

const DOT = {
  online: "#5a9216",
  degraded: "#e08b0a",
  offline: "#d64545",
};

function metricClass(v) {
  if (v == null) return "cap-metric-null";
  if (v > 75) return "cap-metric-red";
  if (v >= 60) return "cap-metric-amber";
  return "cap-metric-green";
}

// minutes represented by a "last seen" string; "now" => 0, hours/days => large
function lastSeenMinutes(str = "") {
  const s = str.toLowerCase();
  if (s.includes("now")) return 0;
  const m = s.match(/(\d+)\s*(m|h|d)/);
  if (!m) return 9999;
  const n = Number(m[1]);
  if (m[2] === "m") return n;
  if (m[2] === "h") return n * 60;
  return n * 60 * 24;
}

function lastSeenClass(str) {
  const mins = lastSeenMinutes(str);
  if (mins < 5) return "cap-seen-green";
  if (mins < 30) return "cap-seen-amber";
  return "cap-seen-red";
}

export default function AgentTable({ agents = [], loading = false }) {
  const [sortKey, setSortKey] = useState("status");
  const [sortDir, setSortDir] = useState("asc"); // default: online first

  const sorted = useMemo(() => {
    const copy = [...agents];
    copy.sort((a, b) => {
      let av;
      let bv;
      if (sortKey === "status") {
        av = STATUS_ORDER[a.status] ?? 9;
        bv = STATUS_ORDER[b.status] ?? 9;
      } else if (sortKey === "last_seen") {
        av = lastSeenMinutes(a.last_seen);
        bv = lastSeenMinutes(b.last_seen);
      } else if (["cpu", "memory", "disk"].includes(sortKey)) {
        av = a[sortKey] == null ? -1 : a[sortKey];
        bv = b[sortKey] == null ? -1 : b[sortKey];
      } else {
        av = (a[sortKey] || "").toString().toLowerCase();
        bv = (b[sortKey] || "").toString().toLowerCase();
      }
      if (av < bv) return sortDir === "asc" ? -1 : 1;
      if (av > bv) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return copy;
  }, [agents, sortKey, sortDir]);

  const handleSort = (key) => {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const metric = (v) => (
    <span className={metricClass(v)}>{v == null ? "—" : `${v}%`}</span>
  );

  if (loading) {
    return (
      <div className="cap-table-wrap">
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} className="cap-skel" style={{ height: 16, margin: "8px 0" }} />
        ))}
      </div>
    );
  }

  return (
    <div className="cap-table-wrap">
      <table className="cap-table">
        <thead>
          <tr>
            {COLUMNS.map((c, idx) => (
              <th
                key={idx}
                onClick={() => handleSort(c.key)}
                className={`${c.numeric ? "num" : ""} ${c.dot ? "dotcol" : ""} ${
                  sortKey === c.key ? "sorted" : ""
                }`}
              >
                {c.label}
                {c.label && (
                  <span className="sort-caret">
                    {sortKey === c.key ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
                  </span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((a, i) => (
            <tr key={a.id ?? i}>
              <td>
                <span className="cap-dot" style={{ background: DOT[a.status] || "#999" }} />
              </td>
              <td className="cap-cell-name">{a.agent_name}</td>
              <td>{a.hostname}</td>
              <td>{a.os}</td>
              <td className="num">{metric(a.cpu)}</td>
              <td className="num">{metric(a.memory)}</td>
              <td className="num">{metric(a.disk)}</td>
              <td className={lastSeenClass(a.last_seen)}>{a.last_seen}</td>
              <td>
                <span className={`cap-badge ${BADGE[a.status] || ""}`}>{a.status}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
