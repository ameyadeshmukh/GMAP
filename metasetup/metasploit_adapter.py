# The program takes the plan made and builds the commands for it to be executed using metaspoit 
class MetasploitAdapter:

    def __init__(self, approved=False):
        self.approved = approved

    def validate(self, plan):

        if plan["requires_approval"] and not self.approved:
            raise Exception("Approval required")

    def prepare(self, plan):
        self.validate(plan)

        commands = [
            f"use {plan['module']}"
        ]

        for k, v in plan["options"].items():
            commands.append(f"set {k} {v}")

        return commands