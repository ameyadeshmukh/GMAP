import subprocess
from parsers.parse_nuclei import parse_nuclei


def vuln_detection_node(state):
    """
    third phase, uses nuclei to scan for known vulnerabilities based on 
    information from the state

    calls the nuclei parser and updates the state
    """


    return state