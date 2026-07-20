from sqlalchemy.future import select
from fastapi import APIRouter , Depends , HTTPException , Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

###############################################
#                                             #
#              LOCAL MODULES IMPORT           #
#                                             #
###############################################
from db.db import  get_async_db
from auth.jwt_auth import verify_token
from datetime import datetime
from schemas.v1.standard_schema import standard_success_response
from schemas.v1.agent_visualisation_schema import (
    CapacityMonitoringOverviewResponse , CapacityMonitoringOverviewSummary
)
from models.event_model import CapacityMonitoringEvents



agent_visualisation_router = APIRouter()




@agent_visualisation_router.get("/capacity-monitoring/overview" ,response_model = standard_success_response[CapacityMonitoringOverviewResponse] , status_code = 200)
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
            M.bandwidth_mbps
        )
        .where(*base_filter)
        .order_by(M.timestamp.asc())
    )
    rows = (await db.execute(series_q)).all()

    def r(v):  # round or pass None through
        return round(v, 2) if v is not None else 0.0
        
    cap_summary = CapacityMonitoringOverviewSummary(
        avg_cpu_percent = r(summary.avg_cpu),
        avg_memory = r(summary.avg_mem),
        avg_agent_cpu_percent = r(summary.avg_agent_cpu_pct),
        avg_agent_memory = r(summary.avg_agent_mem),
        avg_bandwidth_mbps = r(summary.avg_bandwidth)
    )

    cpu_utilization = [
        {"t": row.timestamp, "value": r(row.cpu_percent)} for row in rows
    ]
    memory_utilization = [
        {"t": row.timestamp, "value": r(row.memory_percent)} for row in rows
    ]
    storage_utilization = [
        {"t": row.timestamp, "value": r(row.disk_percent)} for row in rows
    ]
    agent_cpu_utilization = [
        {"t": row.timestamp, "value": r(row.agent_cpu_percent)} for row in rows
    ]
    agent_memory_utilization = [
        {"t": row.timestamp, "value": r(row.agent_rss_mb)} for row in rows
    ]
    agent_bandwidth_mbps = [
        {"t": row.timestamp, "value": r(row.bandwidth_mbps)} for row in rows
    ]

    response = CapacityMonitoringOverviewResponse(
        agent_name = agent_name,
        from_dt = from_dt,
        to_dt = to_dt,
        sample_count = summary.sample_count,
        summary = cap_summary,
        cpu_utilization_series = cpu_utilization,
        memory_utilization_series = memory_utilization,
        storage_utilization_series = storage_utilization,
        agent_cpu_utilization_series = agent_cpu_utilization,
        agent_memory_utilization_series = agent_memory_utilization,
        agent_bandwidth_mbps_series = agent_bandwidth_mbps
    )
    return standard_success_response(data=response , message= "Capacity monitoring overview data get successfully" )