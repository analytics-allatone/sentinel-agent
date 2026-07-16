from pydantic import BaseModel
from datetime import datetime



class CapacityMonitoringOverviewSummary(BaseModel):
    avg_cpu_percent : float
    avg_memory : float
    avg_agent_cpu_percent : float
    avg_agent_memory : float
    avg_bandwidth_mbps : float




class CapacityMonitoringOverviewResponse(BaseModel):
    agent_name : str
    from_dt : datetime
    to_dt : datetime
    sample_count : int
    summary : CapacityMonitoringOverviewSummary
    cpu_utilization_series : list
    memory_utilization_series : list
    storage_utilization_series : list
    agent_cpu_utilization_series : list
    agent_memory_utilization_series : list
    agent_bandwidth_mbps_series : list