from pprint import pprint

from tool_nmap import NmapTool, ScanPolicy
from parse_nmap import normalize_nmap_xml_to_json

nmap = NmapTool()

# Example of a new policy being made
policy = ScanPolicy(
    max_targets=10,
    default_top_ports=100,
    allow_all_ports=False,
    tcp_scan_type="-sT", 
)

run = nmap.run(
    intent="TCP_TOP_PORTS",
    targets=["127.0.0.1"],
    policy=policy,
    timeout_s=120,
)
# To see what command is used
print("Args:", " ".join(run.args))
# Version
print("Nmap version:", run.nmap_version.splitlines()[0] if run.nmap_version else "unknown")

# Results in JSON
normalized = normalize_nmap_xml_to_json(run.stdout_xml, run.targets)
pprint(normalized)