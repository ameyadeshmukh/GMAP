# This program is for building the final plan based on the matched rules and the initial discovery results
def build_plan(result: dict, rule) -> dict:
    options = dict(rule.default_options)

    options["RHOSTS"] = result["host"]

    if result.get("port"):
        options.setdefault("RPORT", result["port"])

    return {
        "rule_id": rule.rule_id,
        "scenario": rule.scenario,
        "module": rule.module,
        "options": options,
        "requires_approval": rule.requires_approval,
        "validation_required": rule.validation_required,
    }