import re
import time
from datetime import datetime, timezone

from backend.celery_app import app
from backend.db import get_db
from backend.models import ExecutionTool, JobExecution, ToolRun
from backend.store import all_tools_done, any_tool_failed
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from graph.graph import build_graph



def _extract_host(target_url: str) -> str:
    """Turn the full url into the IP expected by the graph runner."""
    host = re.sub(r"^https?://", "", target_url, flags=re.IGNORECASE)
    host = host.split("/")[0].split(":")[0]
    if host.lower() == "localhost":
        host = "127.0.0.1"
    return host

def _mark_running(db, execution_tool_id: str) -> str:
    """Set execution_tool to running; set parent job_execution to running if still queued.
    Returns the job_execution_id as a string."""
    et = db.query(ExecutionTool).filter_by(id=execution_tool_id).first()
    if not et:
        raise ValueError(f"ExecutionTool {execution_tool_id} not found")
    et.status = "running"
    et.started_at = datetime.now(timezone.utc)
    job_exec = db.query(JobExecution).filter_by(id=et.job_execution_id).first()
    if job_exec and job_exec.status == "queued":
        job_exec.status = "running"
        job_exec.started_at = datetime.now(timezone.utc)
    return str(et.job_execution_id)


def _mark_done(db, execution_tool_id: str, result: dict, job_execution_id: str, input_payload: dict):
    """Set execution_tool to completed, write ToolRun, and close the job if all tools finished."""
    et = db.query(ExecutionTool).filter_by(id=execution_tool_id).first()
    if et:
        et.status = "completed"
        et.completed_at = datetime.now(timezone.utc)
        db.add(ToolRun(
            execution_tool_id=et.id,
            input_parameters=input_payload, # added tool input parameters
            raw_output_json=result,
            exit_code=0,
        ))
        db.flush()

    if all_tools_done(db, job_execution_id):
        final_status = "failed" if any_tool_failed(db, job_execution_id) else "completed"
        job_exec = db.query(JobExecution).filter_by(id=job_execution_id).first()
        if job_exec:
            job_exec.status = final_status
            job_exec.completed_at = datetime.now(timezone.utc)

def _mark_failed(db, execution_tool_id: str, error: str, job_execution_id: str):
    et = db.query(ExecutionTool).filter_by(id=execution_tool_id).first()
    if et:
        et.status = "failed"
        et.completed_at = datetime.now(timezone.utc)
        db.add(ToolRun(
            execution_tool_id=et.id,
            input_parameters={},
            raw_output_json={"error": error},
            exit_code=1,
        ))
        db.flush()
 

# function for standardized JSON tool output
def build_json_tool_result(tool_name: str, execution_id: str, status: str, data: dict = None, error: dict = None):
    return {
        "tool_name": tool_name,
        "execution_id": execution_id,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data or {},
        "error": error
    }

@app.task
def run_graph(target_url: str, execution_tool_id: str):
    """Invoke the LangGraph agent for the given target and track it in the DB."""

    with get_db() as db:
        job_execution_id = _mark_running(db, execution_tool_id)
 
    target_host = _extract_host(target_url)
 
    initial_state = {
        "target_host":         target_host,
        "scope":               [target_host],
        "exclusions":          [],
        "engagement_rules":    "",
        "open_ports":          [],
        "urls_accessible":     [],
        "tech_stack":          [],
        "http_fingerprint":    {},
        "vulnerabilities":     [],
        "msf_modules":         [],
        "attempted_modules":   [],
        "exploitation_result": None,
        "current_phase":       "start",
        "next_action":         "discovery",
        "correlations":        [],
        "iterations":          0,
        "awaiting_human":      False,
        "human_decision":      None,
        "action_log":          [],
        "job_id":              job_execution_id,
        "report":              "",
    }
 
    try:
        graph = build_graph()

        # Stream the graph execution to capture state after each node
        result = None
        for event in graph.stream(initial_state):
            # Each event contains the state after a node completes
            # event is a dict like {"node_name": state_dict}
            for node_name, state in event.items():
                result = state

                # Update the database with intermediate results after each phase
                # This allows the frontend to poll and see progress
                intermediate_output = build_json_tool_result(
                    tool_name="graph",
                    execution_id=execution_tool_id,
                    status="running",
                    data={
                        "report":          state.get("report", ""),
                        "action_log":      state.get("action_log", []),
                        "vulnerabilities": state.get("vulnerabilities", []),
                        "current_phase":   state.get("current_phase", ""),
                        "open_ports":      len(state.get("open_ports", [])),
                        "urls_accessible": len(state.get("urls_accessible", [])),
                    },
                )

                # Update the ToolRun with intermediate state
                with get_db() as db:
                    et = db.query(ExecutionTool).filter_by(id=execution_tool_id).first()
                    if et:
                        # Delete previous ToolRun entries for this execution_tool
                        db.query(ToolRun).filter_by(execution_tool_id=et.id).delete()

                        # Insert new ToolRun with latest state
                        db.add(ToolRun(
                            execution_tool_id=et.id,
                            input_parameters={"target_url": target_url, "target_host": target_host},
                            raw_output_json=intermediate_output,
                            exit_code=0,
                        ))
                        db.commit()

        if result is None:
            raise Exception("Graph execution produced no results")

    except Exception as exc:
        with get_db() as db:
            _mark_failed(db, execution_tool_id, str(exc), job_execution_id)
        raise

    output = build_json_tool_result(
        tool_name="graph",
        execution_id=execution_tool_id,
        status="success",
        data={
            "report":          result.get("report", ""),
            "action_log":      result.get("action_log", []),
            "vulnerabilities": result.get("vulnerabilities", []),
            "current_phase":   result.get("current_phase", ""),
            "open_ports":      len(result.get("open_ports", [])),
            "urls_accessible": len(result.get("urls_accessible", [])),
        },
    )

    input_payload = {"target_url": target_url, "target_host": target_host}

    with get_db() as db:
        _mark_done(db, execution_tool_id, output, job_execution_id, input_payload)

    return output

