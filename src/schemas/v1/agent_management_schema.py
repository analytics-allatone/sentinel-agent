# from pydantic import BaseModel
from typing import Optional
from pydantic import BaseModel, Field, field_validator
 
from utils.crypto import VALID_ENGINES, canon_engine

class AddAgentRequest(BaseModel):
    agent_name : str
    group_id : Optional[int] = None


class AddAgentResponse(BaseModel):
    id : int
    agent_name : str
    group_id: Optional[int] = None





class AgentData(BaseModel):
    id : int
    agent_name : str
    mac_address : str|None
    host_name : str|None
    main_ip : str|None

    all_ips : list|None 
    os : str|None
    release : str|None
    version : str|None
    machine_architecture : str|None
    is_active : bool
    status : Optional[str] = None
    group_name: Optional[str] = None


class AgentStatusCount(BaseModel):
    total : Optional[int] = 0
    active : Optional[int] = 0
    disconnected : Optional[int] = 0
    pending : Optional[int] = 0
    never_connected : Optional[int] = 0


class AgentOSCount(BaseModel):
    os_name:str
    os_count:int


class AgentGroupCount(BaseModel):
    group_name: str
    group_count: int


class GetAgentsResponse(BaseModel):
    agent_status_count : AgentStatusCount
    agent_os_count : list[AgentOSCount]
    agent_group_count : list[AgentGroupCount]
    agents : list[AgentData]




class AvailableEngines(BaseModel):
    engine: str
    service_name : Optional[str] = None
    username:  Optional[str] = None
    password: Optional[str] = None
    is_enable : Optional[bool] = False

class AvailableEnginesResponse(BaseModel):
    available_engines : list[AvailableEngines]

class IsValidAgentNameResponse(BaseModel):
    valid : bool



class ExistingGroup(BaseModel):
    group_id:int
    group_name : str


class ExistingGroupsResponse(BaseModel):
    groups : list[ExistingGroup]


class AgentInstallationCommandResponse(BaseModel):
    installation_command : str

class AddCredentialRequest(BaseModel):
    engine: str = Field(..., description="mysql | mariadb | postgresql | oracle | redis | mongodb")
    user_name: Optional[str] = Field(None, max_length=255)
    password: Optional[str] = Field(None, description="stored encrypted, never returned")
    service_name: Optional[str] = Field(None, description="Oracle service name / SID")
    dbname: Optional[str] = Field(None, description="mysql / postgres / mongo database")
    host: str = "127.0.0.1"
    port: Optional[int] = None
    agent_name: Optional[str] = None
    is_active: bool = True
 
    @field_validator("engine")
    @classmethod
    def _check_engine(cls, v):
        e = canon_engine(v)
        if e not in VALID_ENGINES:
            raise ValueError(f"unsupported engine '{v}'; expected one of {sorted(VALID_ENGINES)}")
        return e
 
    @field_validator("port")
    @classmethod
    def _check_port(cls, v):
        if v is not None and not (1 <= v <= 65535):
            raise ValueError("port must be between 1 and 65535")
        return v
 
 
class CredentialData(BaseModel):
    id: int
    agent_name: Optional[str] = None
    engine: str
    host: str
    port: Optional[int] = None
    user_name: Optional[str] = None
    service_name: Optional[str] = None
    dbname: Optional[str] = None
    is_active: bool
    has_password: bool
 
 
class AddCredentialResponse(BaseModel):
    credential: CredentialData
    created: bool
 
 
class GetCredentialsResponse(BaseModel):
    credentials: list[CredentialData]