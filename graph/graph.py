from langgraph.graph import StateGraph, END
from state import PenTestState
from nodes.orchestrator import orchestrator
from nodes.discovery import discovery
from nodes.fingerprinting import fingerprinting
from nodes.vuln_detection import vuln_detection
from nodes.review import review
from nodes.exploitation import exploitation
from nodes.documentation import documentation

"""
    builds the graph and the workflow for execution.

    using lang graph, create the graph, register nodes, add logic for routing

    loop starts with orchestrator
"""

def route(state: PenTestState) -> str:
    return state.get("next_action", "documentation")


def build_graph():
    graph = StateGraph(PenTestState)

    graph.add_node("orchestrator",   orchestrator)
    graph.add_node("discovery",      discovery)
    graph.add_node("fingerprinting", fingerprinting)
    graph.add_node("vuln_detection", vuln_detection)
    graph.add_node("review",   review)
    graph.add_node("exploitation",   exploitation)
    graph.add_node("documentation",  documentation)

    graph.add_conditional_edges("orchestrator", route, {
        "discovery":      "discovery",
        "fingerprinting": "fingerprinting",
        "vuln_detection": "vuln_detection",
        "review":   "review",
        "exploitation":   "exploitation",
        "documentation":  "documentation",
    })

    graph.add_edge("discovery",      "orchestrator")
    graph.add_edge("fingerprinting", "orchestrator")
    graph.add_edge("vuln_detection", "orchestrator")
    graph.add_edge("review",   "orchestrator")
    graph.add_edge("exploitation",   "orchestrator")
    graph.add_edge("documentation",  END)

    graph.set_entry_point("orchestrator")

    return graph.compile()