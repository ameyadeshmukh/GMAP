from state import PenTestState


def review(state: PenTestState) -> PenTestState:
    """
    pauses the loop to let human make the next decision.
    should definitely be used before exploiting

    should display potential actions to the user and ask for approval

    also should update state
    """
    log = state.get("action_log", [])
    vulnerabilities = state.get("vulnerabilities", [])
    msf_modules = state.get("msf_modules", [])

    print("\n" + "=" * 60)
    print("HUMAN REVIEW REQUIRED")
    print("=" * 60)

    if vulnerabilities:
        print(f"\nVulnerabilities found ({len(vulnerabilities)}):")
        for i, v in enumerate(vulnerabilities, 1):
            print(f"  {i}. [{v.get('severity', 'unknown').upper()}] {v.get('cve_id', v.get('template_id', 'N/A'))}")
            print(f"     URL: {v.get('url', 'N/A')}")
            print(f"     {v.get('description', '')}")
    else:
        print("\nNo vulnerabilities found.")

    if msf_modules:
        print(f"\nMatched Metasploit modules ({len(msf_modules)}):")
        for i, m in enumerate(msf_modules, 1):
            print(f"  {i}. {m}")
    else:
        print("\nNo Metasploit modules matched.")

    print("\nOptions:")
    print("  approve — proceed with exploitation")
    print("  skip    — skip exploitation, go to documentation")
    print("  abort   — abort the engagement entirely")
    print()

    while True:
        decision = input("Your decision: ").strip().lower()
        if decision in ("approve", "skip", "abort"):
            break
        print(f"  Invalid input '{decision}'. Enter: approve, skip, or abort")

    log.append(f"[REVIEW] human decision: {decision}")

    return {
        **state,
        "human_decision": decision,
        "awaiting_human": False,
        "action_log": log,
    }
