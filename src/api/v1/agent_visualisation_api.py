from sqlalchemy.future import select
from fastapi import APIRouter , Depends , HTTPException , status , Query
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path
from typing import Optional
from sqlalchemy import desc ,select, func

###############################################
#                                             #
#              LOCAL MODULES IMPORT           #
#                                             #
###############################################
from db.db import  get_async_db
from auth.jwt_auth import verify_token
from datetime import datetime
# from schemas.v1.standard_schema import standard_success_response
# from schemas.v1.dashboard_schema import (
#     Soc2ReportResponse , AgentsInfo , 
#     Soc2ReportRecentEvent , Soc2ReportSummary ,
#     Soc2ReportAuth , Soc2ReportFile ,
#     Soc2ReportNetwork , Soc2ReportProcess ,
#     Soc2ReportBars 
# )
from models.agent_model import Agents
from models.event_model import CapacityMonitoringEvents



agent_visualisation_router = APIRouter()




@agent_visualisation_router.get("/capacity-monitoring/overview" , status_code = 200)
async def capacityMonitoringOverview(agent_name: str = Query(..., description="Agent to report on"),
                                     from_dt: datetime = Query(..., description="Window start (ISO-8601)"),
                                     to_dt: datetime = Query(..., description="Window end (ISO-8601)"),
                                     db: AsyncSession = Depends(get_async_db) ,
                                     user:dict = Depends(verify_token)
                                     ):
    if from_dt >= to_dt:
        raise HTTPException(status_code=400, detail="from_dt must be before to_dt")

    M = CapacityMonitoringEvents 

    base_filter = [
        M.agent_name == agent_name,
        M.timestamp >= from_dt,
        M.timestamp <= to_dt,
    ]

    # ---- 1. Summary averages (single row) ----
    summary_q = select(
        func.avg(M.cpu_percent).label("avg_cpu"),
        func.avg(M.memory_used_mb).label("avg_mem"),
        func.avg(M.agent_cpu_percent).label("avg_agent_cpu_pct"),
        func.avg(M.agent_rss_mb).label("avg_agent_mem"),
        func.avg(M.bandwidth_mbps).label("avg_bandwidth"),
        func.count().label("sample_count"),
    ).where(*base_filter)

    summary = (await db.execute(summary_q)).one()

    # ---- 2. Timeseries for charts (ordered points) ----
    series_q = (
        select(
            M.timestamp,
            M.cpu_percent,
            M.disk_percent,
            M.agent_cpu_percent,  
            M.agent_rss_mb,
            M.memory_percent,
        )
        .where(*base_filter)
        .order_by(M.timestamp.asc())
    )
    rows = (await db.execute(series_q)).all()

    def r(v):  # round or pass None through
        return round(v, 2) if v is not None else None

    return {
        "agent_name": agent_name,
        "from": from_dt,
        "to": to_dt,
        "sample_count": summary.sample_count,
        "summary": {
            "avg_cpu_percent": r(summary.avg_cpu),
            "avg_memory": r(summary.avg_mem),
            "avg_agent_cpu_percent" : r(summary.avg_agent_cpu_pct),
            "avg_agent_memory" : r(summary.avg_agent_mem),
            "avg_bandwidth_mbps": r(summary.avg_bandwidth),
        },
        "cpu_utilization_series": [
            {"t": row.timestamp, "value": r(row.cpu_percent)} for row in rows
        ],
        "memory_utilization_series": [
            {"t": row.timestamp, "value": r(row.memory_percent)} for row in rows
        ],
        "storage_utilization_series": [
            {"t": row.timestamp, "value": r(row.disk_percent)} for row in rows
        ],
        "agent_cpu_utilization_series": [
            {"t": row.timestamp, "value": r(row.agent_cpu_percent)} for row in rows
        ],
        "agent_memory_utilization_series": [
            {"t": row.timestamp, "value": r(row.agent_rss_mb)} for row in rows
        ],
    }



# @dashboard_router.get("/soc2-report" , response_model = standard_success_response[Soc2ReportResponse] , status_code = 200)
# async def soc2Report(db: AsyncSession = Depends(get_async_db) , user:dict = Depends(verify_token)):
#     all_agents_query = await db.execute(select(Agents))
#     all_agents = all_agents_query.scalars().all()
#     agents_list = []
#     for ag in all_agents:
#         curr_agent = AgentsInfo(
#             id = ag.id,
#             agent_name = ag.agent_name,
#             host_name = ag.host_name,
#             os = ag.os,
#             status = ag.status
#         )
#         agents_list.append(curr_agent)


#     total_events : int 
#     period_days : int
#     critical_events : int
#     agents_monitored : int
#     compliance_score : float
#     compliance_gap : float
#     recent_events : list[Soc2ReportRecentEvent]

    
#     response = Soc2ReportResponse(
#         agents = agents_list
#     )
#     return standard_success_response[Soc2ReportResponse](data=response , message="SOC2 Report Data" )





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

