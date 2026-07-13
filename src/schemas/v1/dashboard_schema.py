from pydantic import Basemodel , Datetime



class AgentsInfo(Basemodel):
    id : int
    name : str
    hostname : str
    os : str
    last_seen : str
    status : str


class Soc2ReportRecentEvent(Basemodel):
    severity : str
    message : str
    category : str
    timestamp : Datetime


class Soc2ReportSummary(Basemodel):
    total_events : int 
    period_days : int
    critical_events : int
    agents_monitored : int
    compliance_score : float
    compliance_gap : float
    recent_events : list[Soc2ReportRecentEvent]


class Soc2ReportBars(Basemodel):
    event_name : str
    event_count : int
    event_percentage : float



class Soc2ReportAuth(Basemodel):
    auth_events : int
    failed_logins : int
    fail_rate : float
    bars : list[Soc2ReportBars]
    recent_events : list[Soc2ReportRecentEvent]

    


class Soc2ReportFile(Basemodel):
    file_events : int
    files_created : int
    files_deleted : int
    files_updated : int
    bars : list[Soc2ReportBars]
    recent_events : list[Soc2ReportRecentEvent]


class Soc2ReportNetwork(Basemodel):
    network_events : int
    ssh : int
    http : int
    https : int
    dns : int
    bars : list[Soc2ReportBars]
    recent_events : list[Soc2ReportRecentEvent]


class Soc2ReportProcess(Basemodel):
    process_events : int
    processes_started : int
    processes_stoped : int
    resource_spikes : int
    bars : list[Soc2ReportBars]
    recent_events : list[Soc2ReportRecentEvent]


class Soc2ReportResponse(Basemodel):
    agents : list[AgentsInfo]
    summary : Soc2ReportSummary
    auth : Soc2ReportAuth
    file : Soc2ReportFile
    network : Soc2ReportNetwork
    process : Soc2ReportProcess




