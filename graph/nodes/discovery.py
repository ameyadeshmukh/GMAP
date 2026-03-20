from parsers.parse_nmap import parse_nmap


def discovery_node(state):
    """
    first phase of pentesting, runs nmap to discover open ports and services

    builds the nmap command for the target using state information
    
    sends the raw output to parse_nmap

    update state
    """

    return state