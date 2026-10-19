import { useState } from "react";

import GrafanaDashboard from "../../components/GrafanaDashboard/GrafanaDashboard";
import "./AgentDetails.css";

// Grafana's own "All" value for a template variable — every agent, every OS,
// which is what the shared dashboard link opens on.
const GRAFANA_ALL = "$__all";

// ─── SVG Gauge ──────────────────────────────────────────────────────────────

// ─── Bar Chart for Actions ────────────────────────────────────────────────────

// ─── Timeline Placeholder ─────────────────────────────────────────────────────

// ─── Date/Time Range Filter ───────────────────────────────────────────────────



// ─── Data Table ───────────────────────────────────────────────────────────────

// ─── Sample Data Generator ───────────────────────────────────────────────────

// ─── Agent Dashboard (Main) ──────────────────────────────────────────────────
export default function AgentDetails() {
  const [darkMode] = useState(true);

  // Default time range: last 7 days

  // Default data if none provided


  // Bar heights scaled to max action

  return (
    <div className={`dashboard-root${darkMode ? "" : " light-mode"}`}>
      

      {/* MAIN DASHBOARD */}
      <div className="dashboard-main">
       
   

        {/* AGENT INFO — the live Grafana dashboard, embedded. The component
            already defaults to this server and dashboard, so only what the
            shared link states is passed here. */}
        <div className="card-0 grafana-card-0">
          <div className="card-0-title">
            Agent Info — live dashboard
          </div>

          <div className="agent-grafana-frame">
            <GrafanaDashboard
              agentName={GRAFANA_ALL}
              os={GRAFANA_ALL}
              from="now-6h"
              to="now"
              timezone="browser"
              // The shared link carries no &kiosk, so Grafana keeps its own
              // chrome inside the frame — same as the Agent Info page.
              kiosk={false}
              helpFooter={false}
              // follow the page rather than the OS, so the frame does not
              // glare white inside the dark theme
              theme={darkMode ? "dark" : "light"}
              title="Agent info — all agents"
              height="100%"
            />
          </div>
        </div>
      </div>
    </div>
  );
}
