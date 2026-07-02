import React, { useState, useRef, useEffect } from "react";
import api from "../api/api";
import "./InstallationProcess.css";

const InstallationProcess = () => {
  // States
  const [selectedOS, setSelectedOS] = useState("windows");
  const [selectedArchitecture, setSelectedArchitecture] = useState("x64");
  const [agentName, setAgentName] = useState("");
  const [serverIP, setServerIP] = useState("");
  const [agentNameAvailable, setAgentNameAvailable] = useState(null);
  const [agentNameChecking, setAgentNameChecking] = useState(false);
  const [agentNameError, setAgentNameError] = useState("");
  const [installationCommand, setInstallationCommand] = useState("");
  const [startCommand, setStartCommand] = useState("");
  const [copied, setCopied] = useState("");

  // Groups (uses a string for the group name, not an id)
  const [groups, setGroups] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState(""); // holds the typed/selected group name
  const [groupsLoading, setGroupsLoading] = useState(false);
  const [groupsError, setGroupsError] = useState("");
  const [groupDropdownOpen, setGroupDropdownOpen] = useState(false);

  // Command generation state
  const [commandLoading, setCommandLoading] = useState(false);
  const [commandError, setCommandError] = useState("");

  // Debounce timer ref
  const debounceTimer = useRef(null);

  // Group combobox refs
  const groupInputRef = useRef(null);
  const groupWrapperRef = useRef(null);

  // OS Architecture mapping
  const architectures = {
    windows: ["x64", "x86"],
    linux: ["x64", "x86", "arm64", "armv7l"],
    mac: ["x64", "arm64"],
  };

  /* ----------------------------- Helpers ----------------------------- */

  // Normalize whatever /v1/existing-groups returns into [{ id, name }]
  const normalizeGroups = (data) => {
    const pickArray = (value) => {
      if (Array.isArray(value)) return value;
      if (!value || typeof value !== "object") return [];

      if (Array.isArray(value.groups)) return value.groups;
      if (Array.isArray(value.data)) return value.data;
      if (value.data && typeof value.data === "object") {
        if (Array.isArray(value.data.groups)) return value.data.groups;
        if (Array.isArray(value.data.items)) return value.data.items;
      }

      const arrKey = Object.keys(value).find((k) => Array.isArray(value[k]));
      return arrKey ? value[arrKey] : [];
    };

    const payload = data?.data?.groups
      ? data.data.groups
      : data?.groups
        ? data.groups
        : data;

    const raw = pickArray(payload);

    return raw.map((g, i) => {
      if (typeof g === "string") return { id: g, name: g };
      if (g && typeof g === "object") {
        const name =
          g.name ??
          g.group_name ??
          g.groupName ??
          g.title ??
          g.label ??
          String(g.id ?? i);
        const id = g.id ?? g._id ?? g.group_id ?? name;
        return { id: String(id), name: String(name) };
      }
      return { id: String(i), name: String(g) };
    });
  };

  // Interpret the validity response
  const parseValidity = (data) => {
    if (typeof data === "boolean") return data;
    if (data && typeof data === "object") {
      const keys = [
        "is_valid",
        "valid",
        "available",
        "is_available",
        "is_valid_agent_name",
      ];
      for (const k of keys) {
        if (typeof data[k] === "boolean") return data[k];
      }
    }
    return true;
  };

  /* --------------------------- Fetch groups --------------------------- */
  useEffect(() => {
    let cancelled = false;

    const fetchGroups = async () => {
      setGroupsLoading(true);
      setGroupsError("");
      try {
        const response = await api.get("/api/v1/existing-groups");
        if (cancelled) return;
        setGroups(normalizeGroups(response.data));
      } catch (error) {
        if (cancelled) return;
        console.error("Error fetching groups:", error);
        setGroupsError("Couldn't load groups. Please try again.");
        setGroups([]);
      } finally {
        if (!cancelled) setGroupsLoading(false);
      }
    };

    fetchGroups();
    return () => {
      cancelled = true;
    };
  }, []);

  /* --------------- Debounced agent name validation -------------------- */
  useEffect(() => {
    if (debounceTimer.current) {
      clearTimeout(debounceTimer.current);
    }

    if (!agentName.trim()) {
      setAgentNameAvailable(null);
      setAgentNameError("");
      return;
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(agentName)) {
      setAgentNameError(
        "Agent name can only contain letters, numbers, hyphens, and underscores",
      );
      setAgentNameAvailable(false);
      return;
    }

    if (agentName.length < 3) {
      setAgentNameError("Agent name must be at least 3 characters long");
      setAgentNameAvailable(false);
      return;
    }

    if (agentName.length > 50) {
      setAgentNameError("Agent name must be less than 50 characters");
      setAgentNameAvailable(false);
      return;
    }

    setAgentNameError("");
    setAgentNameChecking(true);

    debounceTimer.current = setTimeout(async () => {
      try {
        const response = await api.get(
          `/api/v1/is-valid-agent-name?agent_name=${encodeURIComponent(agentName)}`,
        );
        const valid = parseValidity(response.data);
        setAgentNameAvailable(valid);
        if (!valid) {
          setAgentNameError("This agent name is already taken");
        }
      } catch (error) {
        console.error("Error checking agent name:", error);
        setAgentNameAvailable(true);
      } finally {
        setAgentNameChecking(false);
      }
    }, 1000);

    return () => {
      if (debounceTimer.current) {
        clearTimeout(debounceTimer.current);
      }
    };
  }, [agentName]);

  /* ------------------ Close group dropdown on outside click ----------- */
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (
        groupWrapperRef.current &&
        !groupWrapperRef.current.contains(e.target)
      ) {
        setGroupDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Validate server IP
  const isValidIP = (ip) => {
    if (!ip) return false;
    const ipv4Regex =
      /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
    const domainRegex =
      /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
    return ipv4Regex.test(ip) || domainRegex.test(ip);
  };

  /* ------------------- Fetch install/start commands ------------------- */
  const generateCommands = async () => {
    setCommandLoading(true);
    setCommandError("");
    try {
      const params = new URLSearchParams({
        os: selectedOS,
        arch: selectedArchitecture,
        agent_name: agentName,
        server_ip: serverIP,
      });
      // Only add group if it's not empty
      // Works whether the user picked an existing group from the dropdown
      // or typed a brand-new group name that didn't match anything.
      if (selectedGroup.trim()) {
        params.append("group_name", selectedGroup.trim());
      }

      const response = await api.get(
        `/api/v1/agent-installation-command?${params.toString()}`,
      );
      const data = response.data || {};
      const installCmd = data.data?.installation_command || "";
      const startCmd = data.data?.running_command || "";

      setInstallationCommand(installCmd);
      setStartCommand(startCmd);
    } catch (error) {
      console.error("Error generating commands:", error);
      setCommandError(
        "Couldn't generate the installation command. Please try again.",
      );
      setInstallationCommand("");
      setStartCommand("");
    } finally {
      setCommandLoading(false);
    }
  };

  // Called when "Done" is clicked
  const handleDone = () => {
    // All validations are already enforced by the disabled attribute,
    // but we double‑check here just in case.
    if (
      !agentName ||
      !serverIP ||
      !isValidIP(serverIP) ||
      !agentNameAvailable ||
      agentNameError ||
      !selectedGroup.trim()
    ) {
      return;
    }
    generateCommands();
  };

  // Copy to clipboard
  const copyToClipboard = (text, type) => {
    navigator.clipboard.writeText(text);
    setCopied(type);
    setTimeout(() => setCopied(""), 2000);
  };

  // Reset form
  const handleReset = () => {
    setSelectedOS("windows");
    setSelectedArchitecture("x64");
    setAgentName("");
    setServerIP("");
    setSelectedGroup("");
    setGroupDropdownOpen(false);
    setAgentNameAvailable(null);
    setAgentNameError("");
    setInstallationCommand("");
    setStartCommand("");
    setCommandError("");
  };

  // Filtered groups shown in the dropdown based on what's currently typed
  const filteredGroups = (() => {
    const query = selectedGroup.trim().toLowerCase();
    if (!query) return groups;
    return groups.filter((g) => g.name.toLowerCase().includes(query));
  })();

  return (
    <>
      <div className="installation-container">
        <div className="installation-wrapper">
          {/* Header */}
          <div className="installation-header">
            <h1>Install an Agent</h1>
            <p>Set up and configure your agent</p>
          </div>

          {/* Form Section */}
          <div className="installation-form">
            {/* Operating System Selection */}
            <div className="form-section">
              <label className="form-label">
                <span className="label-title">Operating System *</span>
                <span className="label-hint">
                  Which system will run the agent?
                </span>
              </label>
              <div className="os-grid">
                {["windows", "linux", "mac"].map((os) => (
                  <button
                    key={os}
                    className={`os-button ${selectedOS === os ? "active" : ""}`}
                    onClick={() => {
                      setSelectedOS(os);
                      setSelectedArchitecture(architectures[os][0]);
                    }}
                  >
                    <span className="os-icon">
                      {os === "windows" && (
                        <img
                          src="./windows.png"
                          height={40}
                          width={40}
                          alt="Windows"
                        />
                      )}
                      {os === "linux" && (
                        <img
                          src="./linux.png"
                          height={40}
                          width={40}
                          alt="Linux"
                        />
                      )}
                      {os === "mac" && (
                        <img
                          src="./mac-os-logo.png"
                          height={40}
                          width={40}
                          alt="macOS"
                        />
                      )}
                    </span>
                    <span className="os-name">
                      {os.charAt(0).toUpperCase() + os.slice(1)}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Architecture Selection */}
            <div className="form-section">
              <label className="form-label">
                <span className="label-title">Architecture *</span>
                <span className="label-hint">
                  Pick the right one for your system
                </span>
              </label>
              <div className="architecture-grid">
                {architectures[selectedOS].map((arch) => (
                  <button
                    key={arch}
                    className={`arch-button ${selectedArchitecture === arch ? "active" : ""}`}
                    onClick={() => setSelectedArchitecture(arch)}
                  >
                    {arch}
                  </button>
                ))}
              </div>
            </div>

            {/* Agent Name Input */}
            <div className="form-section">
              <label className="form-label">
                <span className="label-title">Agent Name *</span>
                <span className="label-hint">
                  Give your agent a unique name
                </span>
              </label>
              <div className="input-wrapper">
                <input
                  type="text"
                  className={`form-input ${
                    agentName && agentNameError ? "error" : ""
                  } ${agentName && agentNameAvailable ? "success" : ""}`}
                  placeholder="e.g., my-agent-01"
                  value={agentName}
                  onChange={(e) => setAgentName(e.target.value)}
                />
                <div className="input-status">
                  {agentNameChecking && (
                    <span className="checking">
                      <span className="spinner"></span> Checking...
                    </span>
                  )}
                  {!agentNameChecking && agentName && agentNameAvailable && (
                    <span className="available">✓ Available</span>
                  )}
                  {!agentNameChecking && agentName && !agentNameAvailable && (
                    <span className="unavailable">✗ Not Available</span>
                  )}
                </div>
              </div>
              {agentNameError && (
                <div className="error-message">{agentNameError}</div>
              )}
            </div>

            {/* Group Selection (searchable combobox) */}
            <div className="form-section">
              <label className="form-label">
                <span className="label-title">Group *</span>
                <span className="label-hint">
                  Search an existing group or type a new one
                </span>
              </label>

              <div
                className="input-wrapper group-combobox"
                ref={groupWrapperRef}
              >
                <input
                  ref={groupInputRef}
                  type="text"
                  className={`form-input ${selectedGroup.trim() ? "success" : ""}`}
                  placeholder={
                    groupsLoading
                      ? "Loading groups..."
                      : "Search or type a new group"
                  }
                  value={selectedGroup}
                  disabled={groupsLoading}
                  autoComplete="off"
                  onChange={(e) => {
                    setSelectedGroup(e.target.value);
                    setGroupDropdownOpen(true);
                  }}
                  onFocus={() => setGroupDropdownOpen(true)}
                />

                {groupDropdownOpen && !groupsLoading && (
                  <ul className="group-dropdown-list">
                    {groups.length === 0 && (
                      <li className="group-dropdown-empty">
                        No groups yet — type a name to create one
                      </li>
                    )}

                    {groups.length > 0 && filteredGroups.length === 0 && (
                      <li className="group-dropdown-empty">
                        No match — “{selectedGroup.trim()}” will be created as a
                        new group
                      </li>
                    )}

                    {filteredGroups.map((g) => (
                      <li
                        key={g.id}
                        className={`group-dropdown-item ${
                          g.name === selectedGroup ? "active" : ""
                        }`}
                        // onMouseDown (not onClick) so it fires before the
                        // input's onBlur/outside-click handler closes the list
                        onMouseDown={() => {
                          setSelectedGroup(g.name);
                          setGroupDropdownOpen(false);
                        }}
                      >
                        {g.name}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {groupsError && (
                <div className="error-message">{groupsError}</div>
              )}
            </div>

            {/* Server IP Input */}
            <div className="form-section">
              <label className="form-label">
                <span className="label-title">Server IP/Domain *</span>
                <span className="label-hint">
                  Where should the agent connect to?
                </span>
              </label>
              <div className="input-wrapper">
                <input
                  type="text"
                  className={`form-input ${
                    serverIP && !isValidIP(serverIP) ? "error" : ""
                  } ${serverIP && isValidIP(serverIP) ? "success" : ""}`}
                  placeholder="e.g., 192.168.1.100 or server.example.com"
                  value={serverIP}
                  onChange={(e) => setServerIP(e.target.value)}
                />
                <div className="input-status">
                  {serverIP && isValidIP(serverIP) && (
                    <span className="available">✓ Valid</span>
                  )}
                  {serverIP && !isValidIP(serverIP) && (
                    <span className="unavailable">✗ Invalid</span>
                  )}
                </div>
              </div>
            </div>

            {/* Command loading / error */}
            {commandLoading && (
              <div className="form-section">
                <span className="checking">
                  <span className="spinner"></span> Generating commands...
                </span>
              </div>
            )}
            {commandError && (
              <div className="form-section">
                <div className="error-message">{commandError}</div>
              </div>
            )}

            {/* Action Buttons */}
            <div className="action-buttons">
              <button
                className="btn btn-primary"
                onClick={handleDone}
                disabled={
                  !agentName ||
                  !serverIP ||
                  !isValidIP(serverIP) ||
                  !agentNameAvailable ||
                  !!agentNameError ||
                  !selectedGroup.trim() ||
                  commandLoading
                }
              >
                {commandLoading ? "Generating..." : "Done"}
              </button>
              <button className="btn btn-secondary" onClick={handleReset}>
                Reset
              </button>
            </div>

            {/* Installation Command */}
            {installationCommand && (
              <div className="form-section command-section">
                <label className="form-label">
                  <span className="label-title">Installation Command</span>
                  <span className="label-hint">
                    Run this to install the agent
                  </span>
                </label>
                <div className="command-box">
                  <code className="command-text">{installationCommand}</code>
                  <button
                    className={`copy-button ${copied === "install" ? "copied" : ""}`}
                    onClick={() =>
                      copyToClipboard(installationCommand, "install")
                    }
                    title="Copy to clipboard"
                  >
                    {copied === "install" ? "✓ Copied!" : "📋 Copy"}
                  </button>
                </div>
              </div>
            )}

            {/* Start Command */}
            {startCommand && (
              <div className="form-section command-section">
                <label className="form-label">
                  <span className="label-title">Start Agent Command</span>
                  <span className="label-hint">
                    Run this after installation is done
                  </span>
                </label>
                <div className="command-box">
                  <code className="command-text">{startCommand}</code>
                  <button
                    className={`copy-button ${copied === "start" ? "copied" : ""}`}
                    onClick={() => copyToClipboard(startCommand, "start")}
                    title="Copy to clipboard"
                  >
                    {copied === "start" ? "✓ Copied!" : "📋 Copy"}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Info Section */}
          <div className="info-section">
            <div className="info-card">
              {/* <span className="info-icon">ℹ️</span> */}
              <div>
                <h3>Installation Tips</h3>
                <ul>
                  <li className="li">
                    Make sure you pick the right OS and architecture for your
                    machine
                  </li>
                  <li className="li">
                    Double-check that the server IP or domain is reachable
                  </li>
                  <li className="li">
                    Each agent needs a unique name so you can identify it later
                  </li>
                  <li className="li">
                    You might need admin/sudo privileges to run the installation
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default InstallationProcess;
