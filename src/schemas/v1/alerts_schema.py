from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict
 
 
class AlertData(BaseModel):
    model_config = ConfigDict(from_attributes=True)
 
    id: int
    rule_id: Optional[str] = None
    category: Optional[str] = None          
    severity: Optional[int] = None
    severity_label: Optional[str] = None    
    agent_name: Optional[str] = None
    entity: Optional[str] = None
    event_count: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    detail: Optional[str] = None
    technique: Optional[str] = None
 
 
class GetAlertsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    alerts: List[AlertData]