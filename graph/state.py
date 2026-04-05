from typing import TypedDict, Annotated, List, Optional
from langgraph.graph.message import add_messages


class PenTestState(TypedDict):
    """
    Shared state for the pentest agent graph. Used at each stage of the process, 
    this is the essentially the agent's memory that will be needed at each node.
    The orchestrator node reads and updates this at every step of the loop.
    """
    # For Database
    job_id: str

    # target info 
    target_host:      str
    scope:            List[str]   # allowed ip ranges or domains if necessary
    exclusions:       List[str]   # hosts or paths dont want to check if necessary
    engagement_rules: str         # any rules the user optionally sets before pentest

    # discovery outputs (nmap) 
    open_ports:      List[dict]   # port, protocol, service, version

    # fingerprinting outputs (httpx) 
    urls_accessible:  List[str]   
    tech_stack:       List[str]   
    http_fingerprint: dict        # raw httpx output 

    # vuln detection outputs (nuclei) 
    vulnerabilities: List[dict]   # cve_id, severity, url, description, template_id
    msf_modules:     List[str]    # mapped msf modules in order of severity

    # exploitation 
    attempted_modules:    List[str]  # modules already tried 
    exploitation_result:  List[dict]  # module, success, session_type, output

    # orchestrator and planner info 
    current_phase:       str
    next_action:         str
    correlations:        List[str]   
    iterations:          int
    retry_command: Optional[str]

    # human in the loop info
    awaiting_human: bool
    human_decision: Optional[str]    # approve, skip, abort

    # logs
    action_log: List[str]
    messages:   Annotated[list, add_messages]

    # Output
    report: str