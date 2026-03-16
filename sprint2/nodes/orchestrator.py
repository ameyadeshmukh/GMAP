def orchestrator(state):
    """

    this node determines valid actions based on state, uses the LLM to reason
    about the next action, updates state

    this node is used between each step of the pentest loop, uses the planner
    each time by sending state/planner to llm to make guided decisions

    should update state at each run

    """
