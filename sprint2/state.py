class PenTestState:
    """
    State for the graph, held between all nodes
    
    orchestrator receives the state at each step of the loop

    Stores things like target address, discoveries, action results

    basically the agent's memory. should have things like target ip, open ports,
    services running, http fingerprints, etc
    """

    def __init__(self, target):
