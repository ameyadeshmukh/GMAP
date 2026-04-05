from graph import build_graph
from dotenv import load_dotenv
import uuid

"""
Entry point of the system. invokes the graph and starts everything up
"""

load_dotenv()

def main():
    graph = build_graph()
    # needs to get integrated with frontend
    initial_state = {
        "target_host":         "172.17.0.2",
        "scope":               ["172.17.0.2"],
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
        "job_id": str(uuid.uuid4()),
        "report":              "",
    }

    result = graph.invoke(initial_state)

    print("\n=== ACTION LOG ===")
    for entry in result["action_log"]:
        print(entry)

    print("\n=== REPORT ===")
    print(result.get("report", "no report generated"))


if __name__ == "__main__":
    main()