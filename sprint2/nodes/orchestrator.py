def orchestrator(state):
    """

    this node determines valid actions based on state, uses the LLM to reason
    about the next action, updates state

    this node is used between each step of the pentest loop, uses the planner
    each time by sending state/planner to llm to make guided decisions


    """
SYSTEM_PROMPT = """You are the orchestrator node of an autonomous penetration testing pipeline.

At each step of the process, you will receive the current pentest state along with guidance from the planner.

Your job is to: 
- Analyze the results of the last phase
- Identify correlations between findings and other knowledge
- Decide whether to proceed to the next phase, repeat the current phase, or abort

...


}"""

def orchestrator(state: PenTestState) -> PenTestState:

    # build state summary for LLM

    # feed llm state info, system prompt, and info from planner 

    # the llm should reason over the actions and the state to determine the next action

    # should return the next action with params and info for the next node