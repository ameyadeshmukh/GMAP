from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

def normalize_nmap_xml_to_json(xml_text: str, targets: List[str]) -> Dict[str, Any]:
    """
    Parses nmap XML output (-oX flag) into structured discovery data for the agent state.

    Command that produces this output (from actions.py):
        nmap -sV -p- --open -T4 {target_host}

    Returns a dict with:
        scan   - metadata about the run (tool, targets, timestamp)
        hosts  - per-host results, each containing ip, status, hostnames,
                 and a list of open ports with service/version info
                 (maps to state.open_ports)
    """
    # Creates the JSON Structure for the output
    result: Dict[str, Any] = {
        "scan": {
            "tool": "nmap",
            "targets": targets,
            "timestamp": int(time.time()),
        },
        "hosts": [],
    }
     # Condtion for empty scan results
    if not xml_text.strip():
        return result

# For the elements to be searched
    root = ET.fromstring(xml_text)
   # Searches through the hosts and ignores the hosts that are down since its not relevant for the Agentic AI
    for host in root.findall("host"):
        status_el = host.find("status")
        status = status_el.attrib.get("state") if status_el is not None else "unknown"

        if status != "up":
            continue
        # Takes ipv4 address entries/ validates it
        ip_el = host.find("address[@addrtype='ipv4']")
        if ip_el is None:
            continue
        # Then reads the value
        ip = ip_el.attrib.get("addr")
        if not ip:
            continue
        # Finds the hostname vaule if there is one 
        hostnames: List[str] = []
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            for hostname_el in hostnames_el.findall("hostname"):
                name = hostname_el.attrib.get("name")
                if name:
                    hostnames.append(name)
        # Creates the host object
        host_data: Dict[str, Any] = {
            "ip": ip,
            "status": status,
            "hostnames": hostnames,
            "ports": [],
        }
        # This part of code extracts information about the ports found such as port, protol, state, etc
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                protocol = port_el.attrib.get("protocol")
                portid = port_el.attrib.get("portid")

                state_el = port_el.find("state")
                port_state = state_el.attrib.get("state") if state_el is not None else "unknown"
                # Ignores closed ports 
                if port_state != "open":
                    continue

                try:
                    port_number = int(portid) if portid is not None else None
                except ValueError:
                    port_number = portid
               # Then creats the port object
                port_data: Dict[str, Any] = {
                    "port": port_number,
                    "protocol": protocol,
                    "state": port_state,
                    "service": None,
                }
                # Gets the serivce information then stores it
                service_el = port_el.find("service")
                if service_el is not None:
                    port_data["service"] = {
                        "name": service_el.attrib.get("name"),
                        "product": service_el.attrib.get("product"),
                        "version": service_el.attrib.get("version"),
                    }
                # Adds ports to host
                host_data["ports"].append(port_data)
        # Then adds hosts to the resulting JSON list
        result["hosts"].append(host_data)

    return result