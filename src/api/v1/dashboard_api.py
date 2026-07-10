# from sqlalchemy.future import select
# from fastapi import APIRouter , Depends , HTTPException , status , Query
# from sqlalchemy.ext.asyncio import AsyncSession
# from pathlib import Path
# from typing import Optional
# from sqlalchemy import desc ,select, func

# ###############################################
# #                                             #
# #              LOCAL MODULES IMPORT           #
# #                                             #
# ###############################################
# from db.db import  get_async_db
# from auth.jwt_auth import verify_token
# from schemas.v1.standard_schema import standard_success_response




# dashboard_router = APIRouter()






# @dashboard_router.get("/soc2-report" , response_model = standard_success_response[AddAgentResponse] , status_code = 201)
# async def getAgents(req: AddAgentRequest , db: AsyncSession = Depends(get_async_db) , user:dict = Depends(verify_token)):

#   return {
#     agents: [
#       { id: 1, name: "linux_test", hostname: "redis-allatone", os: "Oracle Linux", last_seen: "now", status: "online" },
#       { id: 2, name: "win_test", hostname: "WIN-SERVER-01", os: "Windows Server 2022", last_seen: "now", status: "online" },
#       { id: 3, name: "linux_test4", hostname: "app-server", os: "Ubuntu 22.04", last_seen: "2m ago", status: "online" },
#       { id: 4, name: "linux_test9", hostname: "web-server", os: "CentOS 8", last_seen: "8m ago", status: "online" },
#       { id: 5, name: "linux_test5", hostname: "db-server", os: "Oracle Linux", last_seen: "12m ago", status: "degraded" },
#       { id: 6, name: "win_server2", hostname: "BACKUP-01", os: "Windows Server 2019", last_seen: "2h ago", status: "offline" },
#     ],

#     summary: {
#       totalEvents: "48,293",
#       period: "30 day period",
#       criticalEvents: "142",
#       agentsMonitored: "6",
#       complianceScore: 87,
#       complianceGap: "13% gap",
#       criteria: [
#         { key: "cc6", label: "CC6 — Logical access", value: 92 },
#         { key: "cc7", label: "CC7 — System operations", value: 85 },
#         { key: "cc8", label: "CC8 — Change management", value: 78 },
#         { key: "cc9", label: "CC9 — Risk mitigation", value: 91 },
#         { key: "a1", label: "A1 — Availability", value: 95 },
#       ],
#       recentEvents: [
#         { severity: "critical", message: "Privilege escalation — pid 3841", category: "auth", timestamp: "Jun 28" },
#         { severity: "critical", message: "Port scan from 203.0.113.45", category: "network", timestamp: "Jun 27" },
#         { severity: "high", message: "Sensitive file modified /etc/passwd", category: "file", timestamp: "Jun 25" },
#         { severity: "high", message: "Login failed ×5 — user admin", category: "auth", timestamp: "Jun 24" },
#         { severity: "medium", message: "Unusual outbound traffic on eth1", category: "network", timestamp: "Jun 22" },
#       ],
#     },

#     access: {
#       authEvents: "3,241",
#       failedLogins: "48",
#       failRate: "1.5% failure rate",
#       privEscalations: "3",
#       cc6Score: 92,
#       bars: {
#         successful: "3,190", successfulPct: 98,
#         failed: "48", failedPct: 12,
#         locked: "4", lockedPct: 6,
#         mfa: "2,841", mfaPct: 68,
#       },
#       events: [
#         { severity: "critical", message: "Privilege escalation — pid 3841", category: "auth", timestamp: "Jun 28 14:52" },
#         { severity: "critical", message: "Failed login ×5 — user admin", category: "auth", timestamp: "Jun 24 09:11" },
#         { severity: "medium", message: "Token expiry — session refreshed ops", category: "auth", timestamp: "Jun 21 16:40" },
#         { severity: "low", message: "2FA verified — user ashish", category: "auth", timestamp: "Jun 20 08:33" },
#         { severity: "low", message: "User admin logged in from 10.0.0.4", category: "auth", timestamp: "Jun 19 11:05" },
#       ],
#     },

#     sysops: {
#       processEvents: "2,487",
#       anomalies: "14",
#       avgCpu: 34,
#       cc7Score: 85,
#       bars: { avgCpu: 34, avgMem: 61, peakCpu: 78, diskIo: 42 },
#       events: [
#         { severity: "critical", message: "OOM killer invoked — pid 2201", category: "process", timestamp: "Jun 20" },
#         { severity: "high", message: "High CPU — pid 3841 (nginx)", category: "process", timestamp: "Jun 18" },
#         { severity: "medium", message: "Process nginx restarted exit code 1", category: "process", timestamp: "Jun 15" },
#         { severity: "low", message: "Guardlynx-agent started successfully", category: "process", timestamp: "Jun 10" },
#         { severity: "low", message: "Config reloaded — no changes", category: "process", timestamp: "Jun 08" },
#       ],
#     },

#     change: {
#       fileEvents: "1,203",
#       configChanges: "24",
#       binaryChanges: "7",
#       cc8Score: 78,
#       bars: {
#         log: "892", logPct: 74,
#         config: "24", configPct: 30,
#         binary: "7", binaryPct: 8,
#         other: "280", otherPct: 23,
#       },
#       events: [
#         { severity: "critical", message: "/etc/passwd modified", category: "file", timestamp: "Jun 25" },
#         { severity: "critical", message: "/usr/bin/ssh modified", category: "file", timestamp: "Jun 22" },
#         { severity: "medium", message: "/etc/nginx/nginx.conf changed", category: "file", timestamp: "Jun 18" },
#         { severity: "medium", message: "/etc/crontab modified", category: "file", timestamp: "Jun 14" },
#         { severity: "low", message: "/var/log/audit/audit.log updated", category: "file", timestamp: "Jun 10" },
#       ],
#     },

#     network: {
#       networkEvents: "9,104",
#       blockedConnections: "12",
#       portScans: "2",
#       cc9Score: 91,
#       bars: {
#         clean: "9,090", cleanPct: 99,
#         blocked: "12", blockedPct: 10,
#         scans: "2", scansPct: 5,
#         dns: "4,821", dnsPct: 53,
#       },
#       events: [
#         { severity: "critical", message: "Port scan — 203.0.113.45", category: "network", timestamp: "Jun 27" },
#         { severity: "medium", message: "Unusual outbound 4.2GB on eth1", category: "network", timestamp: "Jun 22" },
#         { severity: "medium", message: "Outbound blocked by firewall rule", category: "network", timestamp: "Jun 19" },
#         { severity: "low", message: "HTTPS handshake — backend OK", category: "network", timestamp: "Jun 15" },
#         { severity: "low", message: "Load balancer health check passed", category: "network", timestamp: "Jun 12" },
#       ],
#     },

#     incidents: [
#       { date: "2026-06-28", severity: "critical", category: "Auth", description: "Privilege escalation — pid 3841", agent_name: "linux_test", mitre_technique: "T1068" },
#       { date: "2026-06-27", severity: "critical", category: "Network", description: "Port scan from 203.0.113.45", agent_name: "linux_test", mitre_technique: "T1046" },
#       { date: "2026-06-25", severity: "high", category: "File", description: "Sensitive file modified — /etc/passwd", agent_name: "linux_test4", mitre_technique: "T1098" },
#       { date: "2026-06-24", severity: "high", category: "Auth", description: "Failed login ×5 — user admin", agent_name: "win_test", mitre_technique: "T1110" },
#       { date: "2026-06-22", severity: "high", category: "Network", description: "Unusual outbound — 4.2GB in 1hr", agent_name: "linux_test5", mitre_technique: "T1041" },
#       { date: "2026-06-20", severity: "high", category: "Process", description: "OOM killer invoked — pid 2201", agent_name: "linux_test", mitre_technique: "T1499" },
#       { date: "2026-06-18", severity: "high", category: "File", description: "Binary modified — /usr/bin/ssh", agent_name: "linux_test4", mitre_technique: "T1574" },
#       { date: "2026-06-15", severity: "medium", category: "Auth", description: "Token expiry — session refreshed", agent_name: "win_test", mitre_technique: "T1078" },
#     ],

#     recommendations: [
#       { priority: "critical", text: "Investigate privilege escalation on linux_test (Jun 28, T1068). Enable mandatory MFA for all privileged accounts and audit sudoers configuration. This is a CC6 critical finding." },
#       { priority: "critical", text: "Review binary modification on /usr/bin/ssh (Jun 18, T1574). Verify file integrity against known good hash and investigate who made the change outside the change window." },
#       { priority: "warning", text: "CC8 score is 78% — lowest of all criteria. Implement a mandatory change approval workflow. 7 binary file modifications and 24 config changes were made outside approved windows this period." },
#       { priority: "warning", text: "Configure network egress alerts for traffic exceeding 2GB/hr. The Jun 22 incident (4.2GB on eth1, T1041) was detected reactively. Proactive alerting would have caught it earlier." },
#       { priority: "info", text: "win_server2 (BACKUP-01) has been offline for 2+ hours. Verify the agent service is running and reinstall via the install script if needed." },
#       { priority: "info", text: "Memory utilization averaging 61% across agents with peaks at 78%. Consider increasing RAM on linux_test or reviewing the OOM killer events to prevent future process kills (T1499)." },
#     ],
#   };
# }




# @dashboard_router.get("/capacity-monitoring" , response_model = standard_success_response[AddAgentResponse] , status_code = 201)
# async def getAgents(req: AddAgentRequest , db: AsyncSession = Depends(get_async_db) , user:dict = Depends(verify_token)):
  
#     const AGENTS = [
#     { "id": 1, "agent_name": "linux_test", "hostname": "redis-allatone", os: "Oracle Linux", cpu: 78, memory: 89, disk: 74, status: "online", last_seen: "now" },
#     { "id": 2, "agent_name": "win_test", "hostname": "WIN-SERVER-01", os: "Windows 2022", cpu: 61, memory: 72, disk: 68, status: "online", last_seen: "now" },
#     { "id": 3, "agent_name": "linux_test4", "hostname": "app-server", os: "Ubuntu 22.04", cpu: 34, memory: 48, disk: 52, status: "online", last_seen: "2m ago" },
#     { "id": 4, "agent_name": "linux_test9", "hostname": "web-server", os: "CentOS 8", cpu: 22, memory: 35, disk: 31, status: "online", last_seen: "5m ago" },
#     { "id": 5, "agent_name": "linux_test5", "hostname": "db-server", os: "Oracle Linux", cpu: 28, memory: 41, disk: 44, status: "degraded", last_seen: "12m ago" },
#     { "id": 6, "agent_name": "win_server2", "hostname": "BACKUP-01", os: "Windows 2019", cpu: null, memory: null, disk: null, status: "offline", last_seen: "2h ago" },
#     ];

# const CPU_TREND = [
#   { day: "Mon", value: 45 }, { day: "Tue", value: 55 }, { day: "Wed", value: 40 },
#   { day: "Thu", value: 78 }, { day: "Fri", value: 60 }, { day: "Sat", value: 48 }, { day: "Sun", value: 52 },
# ];
# const MEMORY_TREND = [
#   { day: "Mon", value: 55 }, { day: "Tue", value: 60 }, { day: "Wed", value: 58 },
#   { day: "Thu", value: 89 }, { day: "Fri", value: 70 }, { day: "Sat", value: 62 }, { day: "Sun", value: 59 },
# ];
# const BANDWIDTH_TREND = [
#   { day: "Mon", value: 40 }, { day: "Tue", value: 50 }, { day: "Wed", value: 45 },
#   { day: "Thu", value: 100 }, { day: "Fri", value: 55 }, { day: "Sat", value: 48 }, { day: "Sun", value: 52 },
# ];
# const CONNECTIONS_TREND = [
#   { day: "Mon", value: 48 }, { day: "Tue", value: 52 }, { day: "Wed", value: 50 },
#   { day: "Thu", value: 72 }, { day: "Fri", value: 58 }, { day: "Sat", value: 46 }, { day: "Sun", value: 50 },
# ];
# const DISK_TREND = [
#   { day: "Mon", value: 44 }, { day: "Tue", value: 46 }, { day: "Wed", value: 48 },
#   { day: "Thu", value: 66 }, { day: "Fri", value: 70 }, { day: "Sat", value: 50 }, { day: "Sun", value: 48 },
# ];

# // per-agent helpers (offline agents excluded from the metric bars)
# const onlineAgents = AGENTS.filter((a) => a.cpu != null);
# const perAgent = (metric) =>
#   onlineAgents
#     .map((a) => ({ name: a.agent_name, value: a[metric], displayValue: `${a[metric]}%` }))
#     .sort((x, y) => y.value - x.value);

# export function buildCapacityMock() {
#   // bandwidth per agent (MB/s) — scaled so the highest agent = 100%
#   const bwRaw = [
#     { name: "linux_test5", mbps: 4.2 },
#     { name: "linux_test", mbps: 2.8 },
#     { name: "win_test", mbps: 1.9 },
#     { name: "linux_test4", mbps: 1.2 },
#     { name: "linux_test9", mbps: 0.8 },
#   ];
#   const bwMax = Math.max(...bwRaw.map((b) => b.mbps));
#   const bandwidthPerAgent = bwRaw.map((b) => ({
#     name: b.name,
#     value: Math.round((b.mbps / bwMax) * 100),
#     displayValue: `${b.mbps} MB/s`,
#   }));

#   return {
#     agents: AGENTS,

#     summary: {
#       avg_cpu: 34,
#       peak_cpu: 78,
#       peak_cpu_agent: "linux_test",
#       avg_memory: 61,
#       peak_memory: 89,
#       peak_memory_agent: "linux_test",
#       avg_bandwidth: "2.4 MB/s",
#       peak_bandwidth: "4.2 MB/s",
#       peak_bandwidth_agent: "linux_test5",
#       avg_disk: 48,
#       peak_disk: 74,
#       peak_disk_agent: "linux_test",
#       total_traffic: "14.2 GB",
#       total_connections: "9,104",
#       blocked_connections: 12,
#       file_events: "1,203",
#       data_written: "8.4 GB",
#     },

#     cpu: {
#       cpuTrend: CPU_TREND,
#       memoryTrend: MEMORY_TREND,
#       cpuPerAgent: perAgent("cpu"),
#       memoryPerAgent: perAgent("memory"),
#       events: [
#         { severity: "critical", message: "linux_test — CPU spike 78% — pid 3841", timestamp: "Jun 28" },
#         { severity: "high", message: "win_test — sustained 61% for 2h", timestamp: "Jun 26" },
#         { severity: "high", message: "linux_test — OOM killer invoked pid 2201", timestamp: "Jun 24" },
#         { severity: "low", message: "linux_test4 — CPU normalized after restart", timestamp: "Jun 22" },
#       ],
#     },

#     network: {
#       bandwidthTrend: BANDWIDTH_TREND,
#       connectionsTrend: CONNECTIONS_TREND,
#       bandwidthPerAgent,
#       protocols: [
#         { name: "HTTPS", value: 71, color: "blue" },
#         { name: "HTTP", value: 14, color: "amber" },
#         { name: "DNS", value: 10, color: "green" },
#         { name: "Other", value: 5, color: "#999" },
#       ],
#     },

#     storage: {
#       diskPerAgent: perAgent("disk"),
#       diskTrend: DISK_TREND,
#       fileTypes: [
#         { name: "Log files", value: 74, color: "blue" },
#         { name: "Config files", value: 14, color: "amber" },
#         { name: "Binaries", value: 8, color: "red" },
#         { name: "Other", value: 4, color: "#999" },
#       ],
#     },

#     alerts: [
#       { id: 1, priority: "critical", description: "linux_test memory at 89% — OOM killer invoked on Jun 24 (pid 2201). Consider increasing RAM or reviewing memory-heavy processes. Threshold: 85%.", agent_name: "linux_test", resolved: false },
#       { id: 2, priority: "critical", description: "win_server2 offline for 2+ hours. Last seen Jul 1 at 04:00. Verify NSSM service is running: Get-Service Guardlynx-agent on BACKUP-01.", agent_name: "win_server2", resolved: false },
#       { id: 3, priority: "warning", description: "linux_test5 degraded — event reporting gaps detected. Last full heartbeat 12 minutes ago. Check MQTT broker connectivity from db-server.", agent_name: "linux_test5", resolved: false },
#       { id: 4, priority: "warning", description: "linux_test5 bandwidth spike to 4.2 MB/s on Jun 22 — 75% above baseline. Configure egress alert at 3 MB/s to catch this proactively next time.", agent_name: "linux_test5", resolved: false },
#       { id: 5, priority: "warning", description: "linux_test disk usage at 74% and trending upward. At current growth rate, disk will reach 85% threshold in approximately 9 days.", agent_name: "linux_test", resolved: false },
#       { id: 6, priority: "warning", description: "win_test memory averaging 72% over 7 days. Above the 70% watch threshold. Review running services and consider adding a memory alert for this agent.", agent_name: "win_test", resolved: false },
#       { id: 7, priority: "resolved", description: "Resolved — linux_test CPU spike on Jun 28 normalized after nginx restart. Peak was 78%, now averaging 34%. No further action needed.", agent_name: "linux_test", resolved: true },
#       { id: 8, priority: "resolved", description: "Resolved — linux_test4 CPU issue resolved after config reload on Jun 22. Back to normal operating range (34%).", agent_name: "linux_test4", resolved: true },
#     ],
#   };
# }

