from graph.nodes.discovery import discovery
from graph.nodes.fingerprinting import fingerprinting

# fake state for test
state = {
    "target_host":        "172.17.0.2",
    "scope":              ["172.17.0.2"],
    "exclusions":         [],
    "engagement_rules":   "test only",
    "open_ports":         [],
    "urls_accessible":    [],
    "tech_stack":         [],
    "http_fingerprint":   {},
    "vulnerabilities":    [],
    "msf_modules":        [],
    "attempted_modules":  [],
    "exploitation_result": None,
    "next_action":        "discovery",
    "correlations":       [],
    "iterations":         0,
    "awaiting_human":     False,
    "human_decision":     None,
    "action_log":         [],
    "report":             "",
}

# test discovery
print("DISCOVERY")
state = discovery(state)
print("open_ports:", state["open_ports"])
print("action_log:", state["action_log"])

# test fingerprinting node using the discovery results
print("\nFINGERPRINTING")
state = fingerprinting(state)
print("urls_accessible:", state["urls_accessible"])
print("tech_stack:", state["tech_stack"])
print("action_log:", state["action_log"])