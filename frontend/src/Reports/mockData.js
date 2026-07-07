// Realistic fallback data so the UI renders when the SOC2 endpoints
// are not ready yet. Each section mirrors the shape the real API returns.

export function buildMockData() {
  return {
    agents: [
      { id: 1, name: "linux_test", hostname: "redis-allatone", os: "Oracle Linux", last_seen: "now", status: "online" },
      { id: 2, name: "win_test", hostname: "WIN-SERVER-01", os: "Windows Server 2022", last_seen: "now", status: "online" },
      { id: 3, name: "linux_test4", hostname: "app-server", os: "Ubuntu 22.04", last_seen: "2m ago", status: "online" },
      { id: 4, name: "linux_test9", hostname: "web-server", os: "CentOS 8", last_seen: "8m ago", status: "online" },
      { id: 5, name: "linux_test5", hostname: "db-server", os: "Oracle Linux", last_seen: "12m ago", status: "degraded" },
      { id: 6, name: "win_server2", hostname: "BACKUP-01", os: "Windows Server 2019", last_seen: "2h ago", status: "offline" },
    ],

    summary: {
      totalEvents: "48,293",
      period: "30 day period",
      criticalEvents: "142",
      agentsMonitored: "6",
      complianceScore: 87,
      complianceGap: "13% gap",
      criteria: [
        { key: "cc6", label: "CC6 — Logical access", value: 92 },
        { key: "cc7", label: "CC7 — System operations", value: 85 },
        { key: "cc8", label: "CC8 — Change management", value: 78 },
        { key: "cc9", label: "CC9 — Risk mitigation", value: 91 },
        { key: "a1", label: "A1 — Availability", value: 95 },
      ],
      recentEvents: [
        { severity: "critical", message: "Privilege escalation — pid 3841", category: "auth", timestamp: "Jun 28" },
        { severity: "critical", message: "Port scan from 203.0.113.45", category: "network", timestamp: "Jun 27" },
        { severity: "high", message: "Sensitive file modified /etc/passwd", category: "file", timestamp: "Jun 25" },
        { severity: "high", message: "Login failed ×5 — user admin", category: "auth", timestamp: "Jun 24" },
        { severity: "medium", message: "Unusual outbound traffic on eth1", category: "network", timestamp: "Jun 22" },
      ],
    },

    access: {
      authEvents: "3,241",
      failedLogins: "48",
      failRate: "1.5% failure rate",
      privEscalations: "3",
      cc6Score: 92,
      bars: {
        successful: "3,190", successfulPct: 98,
        failed: "48", failedPct: 12,
        locked: "4", lockedPct: 6,
        mfa: "2,841", mfaPct: 68,
      },
      events: [
        { severity: "critical", message: "Privilege escalation — pid 3841", category: "auth", timestamp: "Jun 28 14:52" },
        { severity: "critical", message: "Failed login ×5 — user admin", category: "auth", timestamp: "Jun 24 09:11" },
        { severity: "medium", message: "Token expiry — session refreshed ops", category: "auth", timestamp: "Jun 21 16:40" },
        { severity: "low", message: "2FA verified — user ashish", category: "auth", timestamp: "Jun 20 08:33" },
        { severity: "low", message: "User admin logged in from 10.0.0.4", category: "auth", timestamp: "Jun 19 11:05" },
      ],
    },

    sysops: {
      processEvents: "2,487",
      anomalies: "14",
      avgCpu: 34,
      cc7Score: 85,
      bars: { avgCpu: 34, avgMem: 61, peakCpu: 78, diskIo: 42 },
      events: [
        { severity: "critical", message: "OOM killer invoked — pid 2201", category: "process", timestamp: "Jun 20" },
        { severity: "high", message: "High CPU — pid 3841 (nginx)", category: "process", timestamp: "Jun 18" },
        { severity: "medium", message: "Process nginx restarted exit code 1", category: "process", timestamp: "Jun 15" },
        { severity: "low", message: "Guardlynx-agent started successfully", category: "process", timestamp: "Jun 10" },
        { severity: "low", message: "Config reloaded — no changes", category: "process", timestamp: "Jun 08" },
      ],
    },

    change: {
      fileEvents: "1,203",
      configChanges: "24",
      binaryChanges: "7",
      cc8Score: 78,
      bars: {
        log: "892", logPct: 74,
        config: "24", configPct: 30,
        binary: "7", binaryPct: 8,
        other: "280", otherPct: 23,
      },
      events: [
        { severity: "critical", message: "/etc/passwd modified", category: "file", timestamp: "Jun 25" },
        { severity: "critical", message: "/usr/bin/ssh modified", category: "file", timestamp: "Jun 22" },
        { severity: "medium", message: "/etc/nginx/nginx.conf changed", category: "file", timestamp: "Jun 18" },
        { severity: "medium", message: "/etc/crontab modified", category: "file", timestamp: "Jun 14" },
        { severity: "low", message: "/var/log/audit/audit.log updated", category: "file", timestamp: "Jun 10" },
      ],
    },

    network: {
      networkEvents: "9,104",
      blockedConnections: "12",
      portScans: "2",
      cc9Score: 91,
      bars: {
        clean: "9,090", cleanPct: 99,
        blocked: "12", blockedPct: 10,
        scans: "2", scansPct: 5,
        dns: "4,821", dnsPct: 53,
      },
      events: [
        { severity: "critical", message: "Port scan — 203.0.113.45", category: "network", timestamp: "Jun 27" },
        { severity: "medium", message: "Unusual outbound 4.2GB on eth1", category: "network", timestamp: "Jun 22" },
        { severity: "medium", message: "Outbound blocked by firewall rule", category: "network", timestamp: "Jun 19" },
        { severity: "low", message: "HTTPS handshake — backend OK", category: "network", timestamp: "Jun 15" },
        { severity: "low", message: "Load balancer health check passed", category: "network", timestamp: "Jun 12" },
      ],
    },

    incidents: [
      { date: "2026-06-28", severity: "critical", category: "Auth", description: "Privilege escalation — pid 3841", agent_name: "linux_test", mitre_technique: "T1068" },
      { date: "2026-06-27", severity: "critical", category: "Network", description: "Port scan from 203.0.113.45", agent_name: "linux_test", mitre_technique: "T1046" },
      { date: "2026-06-25", severity: "high", category: "File", description: "Sensitive file modified — /etc/passwd", agent_name: "linux_test4", mitre_technique: "T1098" },
      { date: "2026-06-24", severity: "high", category: "Auth", description: "Failed login ×5 — user admin", agent_name: "win_test", mitre_technique: "T1110" },
      { date: "2026-06-22", severity: "high", category: "Network", description: "Unusual outbound — 4.2GB in 1hr", agent_name: "linux_test5", mitre_technique: "T1041" },
      { date: "2026-06-20", severity: "high", category: "Process", description: "OOM killer invoked — pid 2201", agent_name: "linux_test", mitre_technique: "T1499" },
      { date: "2026-06-18", severity: "high", category: "File", description: "Binary modified — /usr/bin/ssh", agent_name: "linux_test4", mitre_technique: "T1574" },
      { date: "2026-06-15", severity: "medium", category: "Auth", description: "Token expiry — session refreshed", agent_name: "win_test", mitre_technique: "T1078" },
    ],

    recommendations: [
      { priority: "critical", text: "Investigate privilege escalation on linux_test (Jun 28, T1068). Enable mandatory MFA for all privileged accounts and audit sudoers configuration. This is a CC6 critical finding." },
      { priority: "critical", text: "Review binary modification on /usr/bin/ssh (Jun 18, T1574). Verify file integrity against known good hash and investigate who made the change outside the change window." },
      { priority: "warning", text: "CC8 score is 78% — lowest of all criteria. Implement a mandatory change approval workflow. 7 binary file modifications and 24 config changes were made outside approved windows this period." },
      { priority: "warning", text: "Configure network egress alerts for traffic exceeding 2GB/hr. The Jun 22 incident (4.2GB on eth1, T1041) was detected reactively. Proactive alerting would have caught it earlier." },
      { priority: "info", text: "win_server2 (BACKUP-01) has been offline for 2+ hours. Verify the agent service is running and reinstall via the install script if needed." },
      { priority: "info", text: "Memory utilization averaging 61% across agents with peaks at 78%. Consider increasing RAM on linux_test or reviewing the OOM killer events to prevent future process kills (T1499)." },
    ],
  };
}
