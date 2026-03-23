def orchestrator(state):
    """

    this node determines valid actions based on state, uses the LLM to reason
    about the next action, updates state

    this node is used between each step of the pentest loop, uses the planner
    each time by sending state/planner to llm to make guided decisions


    """

PHASE_ORDER = [
    "discovery",
    "fingerprinting",
    "vuln_detection",
    "human_review",
    "exploitation",
    "documentation",
]

ACTION_MAP = {a["id"]: a for a in ACTIONS}

# llm = 


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
    "retry_hint": "<what to change on retry, or null if not retrying>",
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

    # build state summary for LLM

    # feed llm state info, system prompt, and info from planner 

    # the llm should reason over the actions and the state to determine the next action

    # should return the next action with params and info for the next node