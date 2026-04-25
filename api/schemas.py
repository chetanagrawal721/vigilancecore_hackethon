from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    scan_id : str
    status  : str


class StatusResponse(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    scan_id        : str
    status         : str
    findings_total : int = 0
    elapsed_ms     : int = 0
    message        : str = ""


class EnrichedFinding(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    vuln_type       : str
    severity        : str
    contract_name   : str
    function_name   : Optional[str]   = None
    source_file     : str
    start_line      : Optional[int]   = None
    title           : str
    description     : str
    recommendation  : str
    confidence      : float           = 0.0
    cvss_score      : Optional[float] = None
    detector_id     : str
    why_dangerous   : str             = ""
    attack_scenario : str             = ""
    code_fix        : str             = ""
    best_practice   : str             = ""
    swc_reference   : str             = ""


class ScanStatsOut(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    contracts_analyzed : int = 0
    functions_analyzed : int = 0
    functions_skipped  : int = 0
    findings_total     : int = 0
    elapsed_ms         : int = 0


class EnrichedAuditReport(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    scan_id      : str
    source_file  : str
    status       : str
    stats        : ScanStatsOut
    findings     : List[EnrichedFinding]
    tool_version : Optional[str] = None
    created_at   : str