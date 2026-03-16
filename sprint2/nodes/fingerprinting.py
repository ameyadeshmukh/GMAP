import subprocess
from parsers.parse_httpx import parse_httpx


def fingerprinting_node(state):
    """
    second pentesting phase, runs httpx against HTTP services found during
    the discovery phase

    uses the state to figure out what type of scans to run

    call the parser for httpx and update the state
    """

    return state