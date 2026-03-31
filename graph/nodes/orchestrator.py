import json
from typing import Optional
import os
from langchain_openai import ChatOpenAI
from state import PenTestState
from planner.actions import ACTIONS 
from dotenv import load_dotenv
from langchain_core.messages import SystemMessage, HumanMessage
 
"""

    this node determines valid actions based on state, uses the LLM to reason
    about the next action, updates state

    this node is used between each step of the pentest loop, uses the planner
    each time by sending state/planner to llm to make guided decisions


"""

load_dotenv()

PHASE_ORDER = [
    "discovery",
    "fingerprinting",
    "vuln_detection",
    "review",
    "exploitation",
    "documentation",
]

ACTION_MAP = {a["id"]: a for a in ACTIONS}

llm = ChatOpenAI(
    model="gpt-oss-120b",
    api_key=os.getenv("OPENAI_API_KEY"),
    base_url="https://llm-api.arc.vt.edu/api/v1"
)

SYSTEM_PROMPT = """You are the orchestrator of an autonomous penetration testing pipeline.

At each step of the process, you will receive:
1. The current phase that just completed
2. The action definition for that phase (preconditions, guidance, expected output)
3. The current pentest state

Your job is to decide one of these three options:
- ADVANCE: phase produced enough results, move to the next phase
- RETRY:   phase results are incomplete, re-run with adjusted parameters
- ABORT:   target unreachable, out of scope, or error

Use the action's expected_output to decide whether the phase succeeded
Use the action's guidance to determine what should change on a retry

You must respond ONLY with valid JSON:
{
    "decision": "<advance | retry | abort>",
    "reasoning": "<one concise sentence>",
    "retry_command": "<full modified command string, or null if not retrying>",
    "correlations": ["<interesting links between findings>"]
}

Rules:
- ADVANCE if results are acceptable
- RETRY only if results are clearly incomplete AND guidance suggests a fix
- Never retry the same phase more than 5 times
"""


def _get_action(phase: str) -> Optional[dict]:
    return ACTION_MAP.get(phase)


def _next_phase(current: str) -> str:
    try:
        idx = PHASE_ORDER.index(current)
        return PHASE_ORDER[idx + 1] if idx + 1 < len(PHASE_ORDER) else "documentation"
    except ValueError:
        return "documentation"


def _count_retries(log: list[str], phase: str) -> int:
    """get the number of retries for a phase"""
    return sum(1 for entry in log if f"RETRY {phase}" in entry)


def _build_state_summary(state: PenTestState) -> dict:
    """Pull all the relevant fields to feed to the llm"""
    return {
        "target_host":         state.get("target_host"),
        "current_phase":       state.get("current_phase"),
        "iterations":          state.get("iterations", 0),
        "http_fingerprint":    state.get("http_fingerprint", {}), 
        "open_ports":          state.get("open_ports", []),
        "urls_accessible":     state.get("urls_accessible", []),
        "tech_stack":          state.get("tech_stack", []),
        "vulnerabilities":     state.get("vulnerabilities", []),
        "msf_modules":         state.get("msf_modules", []),
        "attempted_modules":   state.get("attempted_modules", []),
        "exploitation_result": state.get("exploitation_result", []),
        "awaiting_human":      state.get("awaiting_human", False),
        "human_decision":      state.get("human_decision"),
        "last_log_entries":    state.get("action_log", [])[-5:],
    }


def _build_prompt(phase: str, action: dict, state_summary: dict) -> str:
    return (
        f"Phase just completed: {phase}\n\n"
        f"Action definition for this phase:\n{json.dumps(action, indent=2)}\n\n"
        f"Current state:\n{json.dumps(state_summary, indent=2)}"
    )

def orchestrator(state: PenTestState) -> PenTestState:
    log = state.get("action_log", [])
    current_phase = state.get("current_phase", "discovery")
    iterations = state.get("iterations", 0)

    # kicks off the loop
    if current_phase == "start":
        log.append("[ORCHESTRATOR] starting → discovery")
        return {**state, "next_action": "discovery", "current_phase": "discovery", "action_log": log}

    # hard stops
    if iterations >= 10:
        log.append("[ORCHESTRATOR] max iterations reached → documentation")
        return {**state, "next_action": "documentation", "action_log": log}

    if state.get("human_decision") == "abort":
        log.append("[ORCHESTRATOR] human aborted → documentation")
        return {**state, "next_action": "documentation", "action_log": log}

    action = _get_action(current_phase)
    if not action:
        log.append(f"[ORCHESTRATOR] unknown phase {current_phase} → documentation")
        return {**state, "next_action": "documentation", "action_log": log}

    # only allows a phase to retry itself 3 times
    retry_count = _count_retries(log, current_phase)
    if retry_count >= 3:
        log.append(f"[ORCHESTRATOR] max retries for {current_phase} → advancing")
        next_phase = _next_phase(current_phase)
        return {
            **state,
            "next_action": next_phase,
            "current_phase": next_phase,  
            "action_log": log,
            "iterations": iterations + 1,
        }

    # call the llm

    state_summary = _build_state_summary(state)
    prompt = _build_prompt(current_phase, action, state_summary)

    response = llm.invoke([
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=prompt)
    ])

    print("[LLM RAW OUTPUT]", response.content)

    # parse llm response
    try:
        clean = response.content.strip().replace("```json", "").replace("```", "")
        decision = json.loads(clean)
    except Exception as e:
        log.append(f"[ORCHESTRATOR] parse error: {e} → advancing")
        decision = {
            "decision": "advance",
            "reasoning": "parse error fallback",
            "retry_command": None,
            "correlations": [],
            "msf_modules": []
        }

    # determine next action
    d = decision.get("decision", "advance").lower()
    if d == "retry":
        next_action = current_phase
        log.append(f"[ORCHESTRATOR] RETRY {current_phase} | {decision.get('reasoning')} | command: {decision.get('retry_command')}")
    elif d == "abort":
        next_action = "documentation"
        log.append(f"[ORCHESTRATOR] ABORT | {decision.get('reasoning')}")
    else:
        next_action = _next_phase(current_phase)
        log.append(f"[ORCHESTRATOR] ADVANCE → {next_action} | {decision.get('reasoning')}")


    correlations = list(set(state.get("correlations", []) + decision.get("correlations", [])))
    msf_modules = list(set(state.get("msf_modules", []) + decision.get("msf_modules", [])))

    return {
        **state,
        "next_action":  next_action,
        "current_phase": next_action,
        "correlations":  correlations,
        "msf_modules":   msf_modules,
        "retry_command": decision.get("retry_command"),
        "action_log":    log,
        "iterations":    iterations + 1,
    }