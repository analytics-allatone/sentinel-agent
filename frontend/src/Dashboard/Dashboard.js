import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import api, { logout } from "../api/api";
import "./Dashboard.css";

const ROWS_PER_PAGE_OPTIONS = [10, 25, 50, 100];
const STATUS_COLORS = {
  active: "#00a86b",
  disconnected: "#c41e3a",
  pending: "#ffd700",
  neverConnected: "#4a4a4a",
};
const OS_COLORS = ["#4a9fd8", "#7cb342", "#f44336", "#9c27b0", "#ff9800"];
const GROUP_COLORS = ["#00a86b", "#4a9fd8", "#f44336", "#9c27b0", "#ff9800"];

// The chart radius is 60, so its real circumference is 2πr ≈ 376.99.
// The original code hardcoded 565 (correct only for r≈90) while still
// drawing circles with r=60, so every slice's stroke-dasharray was sized
// as a fraction of the *wrong* path length — slices rendered visibly
// larger/smaller than their real percentage. This constant fixes that.
const RADIUS = 60;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function Dashboard() {
  const [agents, setAgents] = useState([]);
  const [selectedAgents, setSelectedAgents] = useState(new Set());

  // Chart data — kept as the API's own aggregate counts, not recomputed
  // from the (possibly filtered/paginated) agents table, since these
  // represent the full account-wide picture regardless of what's on screen.
  const [statusCounts, setStatusCounts] = useState({
    active: 0,
    disconnected: 0,
    pending: 0,
    neverConnected: 0,
  });
  const [osStats, setOsStats] = useState([]);
  const [groupStats, setGroupStats] = useState([]);

  // Search
  const [searchTerm, setSearchTerm] = useState("");

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);

  const navigate = useNavigate();

  useEffect(() => {
    fetchAgents();
  }, []);

  const fetchAgents = () => {
    api
      .get("/api/v1/get-agents")
      .then((res) => {
        if (res.data.status !== "success" || !res.data.data) return;
        const data = res.data.data;

        if (data.agents) {
          const transformedAgents = data.agents.map((agent) => ({
            id: agent.id,
            name: agent.agent_name || "",
            macAddress: agent.mac_address || "",
            hostName: agent.host_name || "",
            ipAddress: agent.main_ip || "",
            allIps: agent.all_ips || [],
            group: agent.group_name || "default",
            os: `${agent.os || ""} ${agent.release || ""} ${agent.version || ""}`.trim(),
            architecture: agent.machine_architecture || "",
            version: agent.version || "",
            status:
              agent.status || (agent.is_active ? "active" : "disconnected"),
            isActive: agent.is_active,
          }));
          setAgents(transformedAgents);
        }

        if (data.agent_status_count) {
          const s = data.agent_status_count;
          setStatusCounts({
            active: s.active || 0,
            disconnected: s.disconnected || 0,
            pending: s.pending || 0,
            neverConnected: s.never_connected || 0,
          });
        }

        if (data.agent_os_count) {
          setOsStats(data.agent_os_count);
        }

        if (data.agent_group_count) {
          setGroupStats(data.agent_group_count);
        }
      })
      .catch((error) => {
        console.error("Error fetching agents:", error);
        if (error.response?.status === 401) {
          logout();
        }
      });
  };

  // ---------------------------------------------------------------------
  // Builds cumulative stroke-dasharray/offset segments for a donut chart,
  // against the *real* circumference so slices are proportioned correctly.
  // The chart <g> is also rotated -90deg so the first slice starts at
  // 12 o'clock instead of 3 o'clock.
  // ---------------------------------------------------------------------
  const buildDonutSegments = (items, getCount, getColor) => {
    const total = items.reduce((sum, item) => sum + getCount(item), 0);
    if (total <= 0) return [];

    let cumulative = 0;
    return items.map((item, index) => {
      const count = getCount(item);
      const dasharray = (count / total) * CIRCUMFERENCE;
      const segment = {
        color: getColor(item, index),
        dasharray: dasharray.toFixed(2),
        dashoffset: (-cumulative).toFixed(2),
        percentage: ((count / total) * 100).toFixed(1),
      };
      cumulative += dasharray;
      return segment;
    });
  };

  const statusSegments = useMemo(
    () =>
      buildDonutSegments(
        Object.entries(statusCounts).filter(([, count]) => count > 0),
        ([, count]) => count,
        ([key]) => STATUS_COLORS[key],
      ),
    [statusCounts],
  );

  const osSegments = useMemo(
    () =>
      buildDonutSegments(
        osStats,
        (o) => o.os_count,
        (_, i) => OS_COLORS[i % OS_COLORS.length],
      ),
    [osStats],
  );

  const groupSegments = useMemo(
    () =>
      buildDonutSegments(
        groupStats,
        (g) => g.group_count,
        (_, i) => GROUP_COLORS[i % GROUP_COLORS.length],
      ),
    [groupStats],
  );

  const renderDonut = (segments, emptyColor) => (
    <svg width="150" height="150" viewBox="0 0 150 150">
      <g transform="rotate(-90 75 75)">
        {segments.length > 0 ? (
          segments.map((segment, index) => (
            <circle
              key={index}
              cx="75"
              cy="75"
              r={RADIUS}
              fill="none"
              stroke={segment.color}
              strokeWidth="20"
              strokeDasharray={`${segment.dasharray} ${CIRCUMFERENCE.toFixed(2)}`}
              strokeDashoffset={segment.dashoffset}
            >
              <title>{`${segment.percentage}%`}</title>
            </circle>
          ))
        ) : (
          <circle
            cx="75"
            cy="75"
            r={RADIUS}
            fill="none"
            stroke={emptyColor}
            strokeWidth="20"
            strokeDasharray={`${CIRCUMFERENCE.toFixed(2)} ${CIRCUMFERENCE.toFixed(2)}`}
          />
        )}
      </g>
    </svg>
  );

  // ---------------------------------------------------------------------
  // Search — matches against every visible column of the agents table.
  // ---------------------------------------------------------------------
  const filteredAgents = useMemo(() => {
    const term = searchTerm.trim().toLowerCase();
    if (!term) return agents;

    return agents.filter((agent) =>
      [
        agent.id,
        agent.name,
        agent.macAddress,
        agent.hostName,
        agent.ipAddress,
        agent.os,
        agent.architecture,
        agent.status,
        agent.group,
      ]
        .filter((value) => value !== null && value !== undefined)
        .some((value) => String(value).toLowerCase().includes(term)),
    );
  }, [agents, searchTerm]);

  // Reset to page 1 whenever the search term or page size changes.
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, rowsPerPage]);

  // ---------------------------------------------------------------------
  // Pagination — the "current" page is clamped inline at render time
  // (rather than via a second effect racing the one above) so there's
  // only ever one place that can move the page, avoiding flicker/loops.
  // ---------------------------------------------------------------------
  const totalPages = Math.max(
    1,
    Math.ceil(filteredAgents.length / rowsPerPage),
  );
  const safePage = Math.min(currentPage, totalPages);

  const paginatedAgents = useMemo(() => {
    const start = (safePage - 1) * rowsPerPage;
    return filteredAgents.slice(start, start + rowsPerPage);
  }, [filteredAgents, safePage, rowsPerPage]);

  const rangeStart =
    filteredAgents.length === 0 ? 0 : (safePage - 1) * rowsPerPage + 1;
  const rangeEnd = Math.min(safePage * rowsPerPage, filteredAgents.length);

  const selectAll =
    paginatedAgents.length > 0 &&
    paginatedAgents.every((agent) => selectedAgents.has(agent.id));

  const handleDeployAgent = () => {
    navigate("/installation");
  };

  const handleRefresh = () => {
    fetchAgents();
  };

  const handleExportFormatted = () => {
    if (filteredAgents.length === 0) return;

    const headers = [
      "ID",
      "Agent Name",
      "MAC Address",
      "Host Name",
      "IP Address",
      "Operating System",
      "Architecture",
      "Status",
      "Group",
    ];
    const rows = filteredAgents.map((agent) => [
      agent.id,
      agent.name,
      agent.macAddress,
      agent.hostName,
      agent.ipAddress,
      agent.os,
      agent.architecture,
      agent.status,
      agent.group,
    ]);
    const csv = [headers, ...rows]
      .map((row) =>
        row
          .map((cell) => `"${String(cell ?? "").replace(/"/g, '""')}"`)
          .join(","),
      )
      .join("\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "agents-export.csv";
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleSelectAll = (e) => {
    const newSelected = new Set(selectedAgents);
    if (e.target.checked) {
      paginatedAgents.forEach((agent) => newSelected.add(agent.id));
    } else {
      paginatedAgents.forEach((agent) => newSelected.delete(agent.id));
    }
    setSelectedAgents(newSelected);
  };

  const handleSelectAgent = (agentId) => {
    const newSelected = new Set(selectedAgents);
    if (newSelected.has(agentId)) {
      newSelected.delete(agentId);
    } else {
      newSelected.add(agentId);
    }
    setSelectedAgents(newSelected);
  };

  const handleAgentAction = (agentId, agentName) => {
    alert(`Actions for agent: ${agentName}`);
  };

  const goToPage = (page) => {
    setCurrentPage(Math.min(Math.max(page, 1), totalPages));
  };

  // Compact page-number list with ellipses for large page counts.
  const pageNumbers = useMemo(() => {
    const pages = [];
    const windowSize = 1;
    for (let i = 1; i <= totalPages; i++) {
      if (
        i === 1 ||
        i === totalPages ||
        (i >= safePage - windowSize && i <= safePage + windowSize)
      ) {
        pages.push(i);
      } else if (pages[pages.length - 1] !== "...") {
        pages.push("...");
      }
    }
    return pages;
  }, [totalPages, safePage]);

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>Endpoints</h1>
        <div className="header-actions">
          <button className="btn-deploy" onClick={handleDeployAgent}>
            + Deploy new agent
          </button>
          <button className="btn-refresh" onClick={handleRefresh}>
            ↻ Refresh
          </button>
          <button className="btn-export" onClick={handleExportFormatted}>
            ⬇ Export formatted
          </button>
        </div>
      </div>

      {/* Statistics Section */}
      <div className="stats-section">
        <div className="stat-card">
          <h3>AGENTS BY STATUS</h3>
          <div className="pie-chart">
            {renderDonut(statusSegments, "#cccccc")}
          </div>
          <div className="legend">
            <div className="legend-item">
              <span
                className="legend-color"
                style={{ backgroundColor: STATUS_COLORS.active }}
              ></span>{" "}
              Active ({statusCounts.active})
            </div>
            <div className="legend-item">
              <span
                className="legend-color"
                style={{ backgroundColor: STATUS_COLORS.disconnected }}
              ></span>{" "}
              Disconnected ({statusCounts.disconnected})
            </div>
            <div className="legend-item">
              <span
                className="legend-color"
                style={{ backgroundColor: STATUS_COLORS.pending }}
              ></span>{" "}
              Pending ({statusCounts.pending})
            </div>
            <div className="legend-item">
              <span
                className="legend-color"
                style={{ backgroundColor: STATUS_COLORS.neverConnected }}
              ></span>{" "}
              Never connected ({statusCounts.neverConnected})
            </div>
          </div>
        </div>

        <div className="stat-card">
          <h3>TOP 5 OS</h3>
          <div className="pie-chart">{renderDonut(osSegments, "#cccccc")}</div>
          <div className="legend">
            {osStats.length > 0 ? (
              osStats.map((os, index) => (
                <div key={index} className="legend-item">
                  <span
                    className="legend-color"
                    style={{
                      backgroundColor: OS_COLORS[index % OS_COLORS.length],
                    }}
                  ></span>{" "}
                  {os.os_name} ({os.os_count})
                </div>
              ))
            ) : (
              <div className="legend-item">
                <span
                  className="legend-color"
                  style={{ backgroundColor: "#cccccc" }}
                ></span>{" "}
                No OS data
              </div>
            )}
          </div>
        </div>

        <div className="stat-card">
          <h3>TOP 5 GROUPS</h3>
          <div className="pie-chart">
            {renderDonut(groupSegments, "#00a86b")}
          </div>
          <div className="legend">
            {groupStats.length > 0 ? (
              groupStats.map((group, index) => (
                <div key={index} className="legend-item">
                  <span
                    className="legend-color"
                    style={{
                      backgroundColor:
                        GROUP_COLORS[index % GROUP_COLORS.length],
                    }}
                  ></span>{" "}
                  {group.group_name} ({group.group_count})
                </div>
              ))
            ) : (
              <div className="legend-item">
                <span
                  className="legend-color"
                  style={{ backgroundColor: "#00a86b" }}
                ></span>{" "}
                default (0)
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Agents Table Section */}
      <div className="agents-section">
        <div className="table-header">
          <h2>
            Agents ({filteredAgents.length}
            {filteredAgents.length !== agents.length
              ? ` of ${agents.length}`
              : ""}
            )
          </h2>
          <div className="table-search">
            <input
              type="text"
              className="search-input"
              placeholder="Search all columns…"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            {searchTerm && (
              <button
                type="button"
                className="search-clear"
                onClick={() => setSearchTerm("")}
                aria-label="Clear search"
              >
                ✕
              </button>
            )}
          </div>
        </div>

        <table className="agents-table">
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  checked={selectAll}
                  onChange={handleSelectAll}
                />
              </th>
              <th>ID</th>
              <th>Agent Name</th>
              <th>MAC Address</th>
              <th>Host Name</th>
              <th>IP Address</th>
              <th>Operating System</th>
              <th>Architecture</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {paginatedAgents.length === 0 ? (
              <tr>
                <td colSpan={10} className="no-results">
                  {searchTerm
                    ? `No agents match "${searchTerm}".`
                    : "No agents found."}
                </td>
              </tr>
            ) : (
              paginatedAgents.map((agent) => (
                <tr key={agent.id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedAgents.has(agent.id)}
                      onChange={() => handleSelectAgent(agent.id)}
                    />
                  </td>
                  <td>{agent.id}</td>
                  <td>
                    <a
                      href="/agentDetailsCard"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="agent-name-link"
                    >
                      {agent.name}
                    </a>
                  </td>
                  <td>{agent.macAddress}</td>
                  <td>{agent.hostName}</td>
                  <td>{agent.ipAddress}</td>
                  <td>{agent.os}</td>
                  <td>{agent.architecture}</td>
                  <td>
                    <span className={`status-badge status-${agent.status}`}>
                      ● {agent.status}
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn-action"
                      onClick={() => handleAgentAction(agent.id, agent.name)}
                    >
                      ⋯
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {filteredAgents.length > 0 && (
          <div className="pagination-bar1">
            <div className="pagination-info">
              Showing {rangeStart}–{rangeEnd} of {filteredAgents.length}
            </div>

            <div className="pagination-controls">
              <button
                className="btn-page"
                onClick={() => goToPage(safePage - 1)}
                disabled={safePage === 1}
              >
                ‹ Prev
              </button>

              {pageNumbers.map((page, index) =>
                page === "..." ? (
                  <span
                    key={`ellipsis-${index}`}
                    className="pagination-ellipsis"
                  >
                    …
                  </span>
                ) : (
                  <button
                    key={page}
                    className={`btn-page ${page === safePage ? "btn-page-active" : ""}`}
                    onClick={() => goToPage(page)}
                  >
                    {page}
                  </button>
                ),
              )}

              <button
                className="btn-page"
                onClick={() => goToPage(safePage + 1)}
                disabled={safePage === totalPages}
              >
                Next ›
              </button>
            </div>

            <div className="pagination-size">
              <label htmlFor="rows-per-page">Rows per page</label>
              <select
                id="rows-per-page"
                value={rowsPerPage}
                onChange={(e) => setRowsPerPage(Number(e.target.value))}
              >
                {ROWS_PER_PAGE_OPTIONS.map((size) => (
                  <option key={size} value={size}>
                    {size}
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Dashboard;
