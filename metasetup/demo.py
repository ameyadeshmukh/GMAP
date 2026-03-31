# Demo to show how all the files work together. It takes the result from the matcher, builds a plan and then prepares the commands for metasploit using the adapter.
from matcher import match_rule
from plan_builder import build_plan
from metasploit_adapter import MetasploitAdapter


def run_demo(result):
    rule = match_rule(result)

    if not rule:
        print("No match found")
        return

    plan = build_plan(result, rule)

    adapter = MetasploitAdapter(approved=True)

    commands = adapter.prepare(plan)

    print("\nSelected Rule:", rule.rule_id)
    print("Metasploit Commands:")
    for c in commands:
        print(" ", c)


if __name__ == "__main__":

    result = {
        "source_lab": "vulhub",
        "scenario": "samba/CVE-2007-2447",
        "host": "192.168.56.101",
        "port": 139,
        "service": "smb",
        "product": "samba",
        "cve": "CVE-2007-2447",
    }

    run_demo(result)