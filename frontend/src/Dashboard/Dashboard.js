import { Fragment, useEffect, useMemo, useState } from "react";
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

  // Available-services expansion: which agent row is open, plus a per-agent
  // cache of { loading, error, list } so re-opening a row doesn't refetch.
  const [expandedAgent, setExpandedAgent] = useState(null);
  const [services, setServices] = useState({});

  // Credentials popup: opened by clicking an engine inside the services panel.
  // null when closed, else { agentName, engine, loading, error, data }.
  const [credModal, setCredModal] = useState(null);
  // Which field was just copied to the clipboard (e.g. "2-host"), for the ✓ flash.
  const [copiedField, setCopiedField] = useState("");

  // Edit-credential form inside the popup: null when viewing the list,
  // else the form's field values (payload of POST /api/v1/add-credential).
  const [editCred, setEditCred] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [saveMsg, setSaveMsg] = useState("");

  // Delete-credential flow: which card is asking "are you sure?", and which
  // one is mid-delete.
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);

  const navigate = useNavigate();

  useEffect(() => {
    fetchAgents();
  }, []);

  const fetchAgents = () => {
    api
      .get("/get-agents")
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
    navigate("/app/installation");
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

  // "+" in the first column: expand the row and load that agent's available
  // services. The endpoint queries the agent live over MQTT, so it can time out
  // with a 504 when the agent is offline — that message is surfaced inline.
  const handleToggleServices = (agentName) => {
    if (expandedAgent === agentName) {
      setExpandedAgent(null); // clicking an open row collapses it
      return;
    }
    setExpandedAgent(agentName);

    // Reuse a previous successful result; retry if it failed last time.
    const cached = services[agentName];
    if (cached && !cached.error && cached.list) return;

    setServices((prev) => ({
      ...prev,
      [agentName]: { loading: true, error: "", list: null },
    }));

    api
      .get("/available-services", { params: { agent_name: agentName } })
      .then((res) => {
        const list = res.data?.data?.available_engines || [];
        setServices((prev) => ({
          ...prev,
          [agentName]: { loading: false, error: "", list },
        }));
      })
      .catch((err) => {
        // FastAPI raises HTTPException -> { detail: "..." }
        const msg =
          err.response?.data?.detail ||
          err.response?.data?.message ||
          "Failed to load services for this agent.";
        setServices((prev) => ({
          ...prev,
          [agentName]: { loading: false, error: msg, list: null },
        }));
      });
  };

  const renderServices = (agentName) => {
    const state = services[agentName];

    if (!state || state.loading) {
      return <div className="services-status">Loading available services…</div>;
    }
    if (state.error) {
      return (
        <div className="services-status services-error">
          {state.error}
          <button
            className="services-retry"
            onClick={() => {
              // Clear the cached error so the toggle refetches.
              setServices((prev) => {
                const next = { ...prev };
                delete next[agentName];
                return next;
              });
              setExpandedAgent(null);
              handleToggleServices(agentName);
            }}
          >
            Retry
          </button>
        </div>
      );
    }
    if (!state.list.length) {
      return (
        <div className="services-status">No services available for this agent.</div>
      );
    }

    return (
      <>
      <table className="services-table">
        <thead>
          <tr>
            <th>Engine</th>
            <th>Service Name</th>
            <th>Username</th>
            <th>Status</th>
            <th className="svc-th-action" />
          </tr>
        </thead>
        <tbody>
          {state.list.map((svc, i) => {
            const style = getEngineStyle(svc.engine);
            return (
              <tr
                key={`${svc.engine}-${i}`}
                className="svc-row"
                onClick={() => handleEngineClick(agentName, svc.engine)}
                title={`View ${svc.engine} credentials`}
              >
                <td className="svc-engine">
                  <span className="svc-engine-cell">
                    <span
                      className="engine-avatar engine-avatar-sm"
                      style={{ background: style.color }}
                    >
                      {style.label}
                    </span>
                    <span className="svc-engine-name">{svc.engine}</span>
                  </span>
                </td>
                <td>{svc.service_name || "—"}</td>
                <td>{svc.username || "—"}</td>
                <td>
                  <span className={`cred-chip ${svc.is_enable ? "chip-on" : "chip-off"}`}>
                    <i className="chip-dot" />
                    {svc.is_enable ? "Enabled" : "Disabled"}
                  </span>
                </td>
                <td className="svc-td-action">
                  <span className="svc-view-hint">
                    View credentials <span className="svc-chevron">›</span>
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      </>
    );
  };

  // Clicking an engine (e.g. "mongodb") in the services panel: fetch that
  // engine's credentials for the agent and show them in a popup.
  const handleEngineClick = (agentName, engine) => {
    setEditCred(null);
    setSaveError("");
    setSaveMsg("");
    setCredModal({ agentName, engine, loading: true, error: "", data: null });
    fetchCredentials(agentName, engine);
  };

  const fetchCredentials = (agentName, engine) => {
    api
      .get("/get-credentials", {
        params: { engine, agent_name: agentName },
      })
      .then((res) => {
        const data = res.data?.data ?? res.data;
        setCredModal((prev) =>
          prev && prev.agentName === agentName && prev.engine === engine
            ? { ...prev, loading: false, error: "", data }
            : prev,
        );
      })
      .catch((err) => {
        const msg =
          err.response?.data?.detail ||
          err.response?.data?.message ||
          "Failed to fetch credentials.";
        setCredModal((prev) =>
          prev && prev.agentName === agentName && prev.engine === engine
            ? { ...prev, loading: false, error: msg, data: null }
            : prev,
        );
      });
  };

  const closeCredModal = () => {
    setCredModal(null);
    setEditCred(null);
    setSaveError("");
    setSaveMsg("");
    setConfirmDeleteId(null);
    setDeletingId(null);
  };

  // ── Delete credential (DELETE /api/v1/delete-credential?credential_id=N) ───
  const handleDeleteCred = (credId) => {
    setSaveError("");
    setSaveMsg("");
    setDeletingId(credId);

    api
      .delete("/delete-credential", {
        params: { credential_id: credId },
      })
      .then(() => {
        setDeletingId(null);
        setConfirmDeleteId(null);
        setSaveMsg("Credential deleted successfully.");
        // Refresh the list so the removed credential disappears.
        setCredModal((prev) => (prev ? { ...prev, loading: true } : prev));
        fetchCredentials(credModal.agentName, credModal.engine);
      })
      .catch((err) => {
        setDeletingId(null);
        setConfirmDeleteId(null);
        setSaveError(
          err.response?.data?.detail ||
            err.response?.data?.message ||
            "Failed to delete credential.",
        );
      });
  };

  // ── Edit credential (POST /api/v1/add-credential) ──────────────────────────
  const startEditCred = (cred) => {
    setSaveError("");
    setSaveMsg("");
    setEditCred({
      engine: cred.engine || credModal.engine,
      agent_name: cred.agent_name || credModal.agentName,
      host: cred.host || "",
      port: cred.port ?? "",
      user_name: cred.user_name || "",
      // Never prefill a password — has_password only says one exists.
      password: "",
      service_name: cred.service_name || "",
      dbname: cred.dbname || "",
      is_active: !!cred.is_active,
    });
  };

  const updateEditField = (key, value) =>
    setEditCred((prev) => ({ ...prev, [key]: value }));

  const handleSaveCred = (e) => {
    e.preventDefault();
    setSaveError("");

    if (!editCred.host.trim() || !editCred.user_name.trim()) {
      setSaveError("Host and Username are required.");
      return;
    }

    setSaving(true);
    api
      .post("/add-credential", {
        engine: editCred.engine,
        user_name: editCred.user_name.trim(),
        password: editCred.password,
        service_name: editCred.service_name.trim(),
        dbname: editCred.dbname.trim(),
        host: editCred.host.trim(),
        port: Number(editCred.port) || 0,
        agent_name: editCred.agent_name,
        is_active: editCred.is_active,
      })
      .then(() => {
        setSaving(false);
        setEditCred(null);
        setSaveMsg("Credential saved successfully.");
        // Refresh the list so the popup shows the updated values.
        setCredModal((prev) => (prev ? { ...prev, loading: true } : prev));
        fetchCredentials(credModal.agentName, credModal.engine);
      })
      .catch((err) => {
        setSaving(false);
        setSaveError(
          err.response?.data?.detail ||
            err.response?.data?.message ||
            "Failed to save credential.",
        );
      });
  };

  // Copy a field value to the clipboard and flash a ✓ on that field.
  const copyValue = (fieldKey, value) => {
    if (!navigator.clipboard) return;
    navigator.clipboard
      .writeText(String(value))
      .then(() => {
        setCopiedField(fieldKey);
        setTimeout(
          () => setCopiedField((current) => (current === fieldKey ? "" : current)),
          1200,
        );
      })
      .catch(() => {});
  };

  // Brand-ish accent color + short label per engine for the card avatars.
  const getEngineStyle = (engine) => {
    const key = (engine || "").toLowerCase().replace(/[^a-z]/g, "");
    const styles = {
      postgresql: { color: "#336791", label: "Pg" },
      postgres: { color: "#336791", label: "Pg" },
      mysql: { color: "#00758f", label: "My" },
      mongodb: { color: "#47a248", label: "Mg" },
      oracle: { color: "#c74634", label: "Or" },
      sqlserver: { color: "#a91d22", label: "MS" },
      redis: { color: "#d82c20", label: "Rd" },
    };
    return styles[key] || { color: "#667eea", label: (engine || "?").slice(0, 2) };
  };

  // Response shape: data.credentials = [{ id, agent_name, engine, host, port,
  // user_name, service_name, dbname, is_active, has_password }]
  const renderCredBody = () => {
    if (credModal.loading) {
      return <div className="cred-status">Fetching credentials…</div>;
    }
    if (credModal.error) {
      return <div className="cred-status cred-error">{credModal.error}</div>;
    }

    const credentials = credModal.data?.credentials;
    if (!Array.isArray(credentials) || credentials.length === 0) {
      return (
        <div className="cred-status">
          No credentials found for this engine.
        </div>
      );
    }

    return (
      <>
      {saveMsg && <div className="cred-saved-notice">✓ {saveMsg}</div>}
      {saveError && <div className="cred-status cred-error">{saveError}</div>}
      <div className="cred-count">
        <span className="cred-count-num">{credentials.length}</span>
        credential{credentials.length === 1 ? "" : "s"} found
      </div>
      <div className="cred-list">
        {credentials.map((cred, i) => {
          const style = getEngineStyle(cred.engine);
          const fields = [
            ["Host", cred.host],
            ["Port", cred.port],
            ["Username", cred.user_name],
            ["Service", cred.service_name],
            ["Database", cred.dbname],
          ];
          return (
            <div className="cred-card" key={cred.id ?? i}>
              <div
                className="cred-card-accent"
                style={{ background: style.color }}
              />
              <div className="cred-card-head">
                <span
                  className="engine-avatar"
                  style={{ background: style.color }}
                >
                  {style.label}
                </span>
                <div className="cred-card-titles">
                  <span className="cred-card-engine">
                    {cred.engine || "—"}
                    <span className="cred-id">#{cred.id ?? "—"}</span>
                  </span>
                  <span className="cred-card-agent">{cred.agent_name || "—"}</span>
                </div>
                <div className="cred-card-chips">
                  <span className={`cred-chip ${cred.is_active ? "chip-on" : "chip-off"}`}>
                    <i className="chip-dot" />
                    {cred.is_active ? "Active" : "Inactive"}
                  </span>
                  <span
                    className={`cred-chip ${cred.has_password ? "chip-on" : "chip-warn"}`}
                    title={cred.has_password ? "Password is set" : "No password set"}
                  >
                    <i className="chip-dot" />
                    {cred.has_password ? "Password" : "No password"}
                  </span>
                  <button
                    type="button"
                    className="cred-edit-btn"
                    title="Edit this credential"
                    onClick={() => startEditCred(cred)}
                  >
                    ✎ Edit
                  </button>
                  {confirmDeleteId === cred.id ? (
                    <span className="cred-del-confirm">
                      Delete?
                      <button
                        type="button"
                        className="cred-del-yes"
                        onClick={() => handleDeleteCred(cred.id)}
                        disabled={deletingId === cred.id}
                      >
                        {deletingId === cred.id ? "…" : "Yes"}
                      </button>
                      <button
                        type="button"
                        className="cred-del-no"
                        onClick={() => setConfirmDeleteId(null)}
                        disabled={deletingId === cred.id}
                      >
                        No
                      </button>
                    </span>
                  ) : (
                    <button
                      type="button"
                      className="cred-del-btn"
                      title="Delete this credential"
                      onClick={() => setConfirmDeleteId(cred.id)}
                    >
                      🗑 Delete
                    </button>
                  )}
                </div>
              </div>

              <div className="cred-grid">
                {fields.map(([label, value]) => {
                  const fieldKey = `${cred.id ?? i}-${label}`;
                  const display = value ?? "—";
                  const copyable = value !== null && value !== undefined && value !== "";
                  return (
                    <div className="cred-field" key={label}>
                      <span className="cred-field-label">{label}</span>
                      <span className="cred-field-value">
                        <span className="cred-field-text">{display === "" ? "—" : display}</span>
                        {copyable && (
                          <button
                            type="button"
                            className={`copy-btn ${copiedField === fieldKey ? "copied" : ""}`}
                            title={copiedField === fieldKey ? "Copied!" : `Copy ${label.toLowerCase()}`}
                            onClick={() => copyValue(fieldKey, value)}
                          >
                            {copiedField === fieldKey ? "✓" : "⧉"}
                          </button>
                        )}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
      </>
    );
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
              placeholder="Search…"
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
              <th className="col-expand" aria-label="Show available services" />
              {/* <th>
                <input
                  type="checkbox"
                  checked={selectAll}
                  onChange={handleSelectAll}
                />
              </th> */}
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
                <td colSpan={11} className="no-results">
                  {searchTerm
                    ? `No agents match "${searchTerm}".`
                    : "No agents found."}
                </td>
              </tr>
            ) : (
              paginatedAgents.map((agent) => (
                <Fragment key={agent.id}>
                <tr>
                  <td className="col-expand">
                    <button
                      type="button"
                      className={`btn-expand ${expandedAgent === agent.name ? "open" : ""}`}
                      onClick={() => handleToggleServices(agent.name)}
                      title={
                        expandedAgent === agent.name
                          ? "Hide available services"
                          : "Show available services"
                      }
                      aria-expanded={expandedAgent === agent.name}
                    >
                      {expandedAgent === agent.name ? "−" : "+"}
                    </button>
                  </td>
                  {/* <td>
                    <input
                      type="checkbox"
                      checked={selectedAgents.has(agent.id)}
                      onChange={() => handleSelectAgent(agent.id)}
                    />
                  </td> */}
                  <td>{agent.id}</td>
                  <td>
                    {/* `agent` scopes the SOC2 report to this agent — it becomes
                        agent_name on every /soc2-report/* request. */}
                    <a
                      href={`/app/reports/soc2?agent=${encodeURIComponent(agent.name)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="agent-name-link"
                      title={`Open the SOC2 report for ${agent.name}`}
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
                {expandedAgent === agent.name && (
                  <tr className="services-row">
                    <td colSpan={11}>
                      <div className="services-panel">
                        <div className="services-title">
                          <span className="services-title-icon">🗄</span>
                          Available services — <strong>{agent.name}</strong>
                          {services[agent.name]?.list?.length > 0 && (
                            <span className="services-count">
                              {services[agent.name].list.length}
                            </span>
                          )}
                        </div>
                        {renderServices(agent.name)}
                      </div>
                    </td>
                  </tr>
                )}
                </Fragment>
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

      {/* Credentials popup (opened from the services panel's engine links) */}
      {credModal && (
        <div className="cred-overlay" onClick={closeCredModal}>
          <div
            className="cred-modal"
            role="dialog"
            aria-modal="true"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="cred-head">
              <div>
                <h3 className="cred-title">
                  {editCred
                    ? "Edit Credential"
                    : `${credModal.engine} credentials`}
                </h3>
                <p className="cred-sub">
                  {editCred ? (
                    <>
                      {editCred.engine} on <strong>{editCred.agent_name}</strong>
                    </>
                  ) : (
                    <>
                      Agent: <strong>{credModal.agentName}</strong>
                    </>
                  )}
                </p>
              </div>
              <button
                type="button"
                className="cred-close"
                onClick={closeCredModal}
                aria-label="Close"
              >
                ✕
              </button>
            </div>

            <div className="cred-body">
              {editCred ? (
                /* ── Edit form: POST /api/v1/add-credential ── */
                <form className="cred-form" onSubmit={handleSaveCred}>
                  {saveError && (
                    <div className="cred-status cred-error">{saveError}</div>
                  )}

                  <div className="cred-form-grid">
                    <div className="form-field">
                      <label>Engine</label>
                      <input value={editCred.engine} disabled />
                    </div>
                    <div className="form-field">
                      <label>Agent Name</label>
                      <input value={editCred.agent_name} disabled />
                    </div>
                    <div className="form-field">
                      <label>Host *</label>
                      <input
                        value={editCred.host}
                        placeholder="127.0.0.1"
                        onChange={(e) => updateEditField("host", e.target.value)}
                        disabled={saving}
                      />
                    </div>
                    <div className="form-field">
                      <label>Port</label>
                      <input
                        type="number"
                        min="0"
                        max="65535"
                        value={editCred.port}
                        placeholder="5432"
                        onChange={(e) => updateEditField("port", e.target.value)}
                        disabled={saving}
                      />
                    </div>
                    <div className="form-field">
                      <label>Username *</label>
                      <input
                        value={editCred.user_name}
                        placeholder="db_user"
                        onChange={(e) =>
                          updateEditField("user_name", e.target.value)
                        }
                        disabled={saving}
                      />
                    </div>
                    <div className="form-field">
                      <label>Password</label>
                      <input
                        type="password"
                        value={editCred.password}
                        placeholder="Enter new password"
                        autoComplete="new-password"
                        onChange={(e) =>
                          updateEditField("password", e.target.value)
                        }
                        disabled={saving}
                      />
                    </div>
                    <div className="form-field">
                      <label>Service Name</label>
                      <input
                        value={editCred.service_name}
                        placeholder="postgres"
                        onChange={(e) =>
                          updateEditField("service_name", e.target.value)
                        }
                        disabled={saving}
                      />
                    </div>
                    <div className="form-field">
                      <label>Database</label>
                      <input
                        value={editCred.dbname}
                        placeholder="production_db"
                        onChange={(e) =>
                          updateEditField("dbname", e.target.value)
                        }
                        disabled={saving}
                      />
                    </div>
                  </div>

                  <label className="form-toggle">
                    <input
                      type="checkbox"
                      checked={editCred.is_active}
                      onChange={(e) =>
                        updateEditField("is_active", e.target.checked)
                      }
                      disabled={saving}
                    />
                    <span>Credential is active</span>
                  </label>

                  <div className="cred-form-actions">
                    <button
                      type="button"
                      className="btn-form-cancel"
                      onClick={() => {
                        setEditCred(null);
                        setSaveError("");
                      }}
                      disabled={saving}
                    >
                      Cancel
                    </button>
                    <button type="submit" className="cred-ok" disabled={saving}>
                      {saving ? "Saving…" : "Save Changes"}
                    </button>
                  </div>
                </form>
              ) : (
                renderCredBody()
              )}
            </div>

            {!editCred && (
              <div className="cred-foot">
                <button type="button" className="cred-ok" onClick={closeCredModal}>
                  Close
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
