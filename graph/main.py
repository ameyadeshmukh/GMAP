from graph.graph import build_graph
from dotenv import load_dotenv
import uuid
import sys

load_dotenv()

def main():
    # Default target
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:9090"

    # Split IP and optional port
    if ":" in target:
        ip, port = target.split(":")
        scan_target = f"{ip} -p {port}"
    else:
        ip = target
        port = None
        scan_target = ip  # will let tools scan all ports by default

    graph = build_graph()

    initial_state = {
        "target_host":         scan_target,
        "scope":               [ip],
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