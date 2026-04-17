from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

# creates a catalog of Vulhub related exploits with metadata for matching against the intial discovery results
@dataclass
class VulhubExploitRule:
    rule_id: str
    scenario: str
    source_lab: str
    cve: Optional[str]
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]
    port: Optional[int]

    module: str
    required_options: List[str] = field(default_factory=list)
    default_options: Dict[str, Any] = field(default_factory=dict)

    rank: int = 0
    requires_approval: bool = False
    validation_required: bool = True
    notes: str = ""
    tags: List[str] = field(default_factory=list)


VULHUB_EXPLOIT_CATALOG = [

    # VSFTPD Backdoor
    VulhubExploitRule(
        rule_id="vsftpd_234",
        scenario="vsftpd/2.3.4",
        source_lab="vulhub",
        cve=None,
        service="ftp",
        product="vsftpd",
        version="2.3.4",
        port=21,
        module="exploit/unix/ftp/vsftpd_234_backdoor",
        required_options=["RHOSTS"],
        rank=95,
    ),

    # Samba CVE-2007-2447
    VulhubExploitRule(
        rule_id="samba_2007_2447",
        scenario="samba/CVE-2007-2447",
        source_lab="vulhub",
        cve="CVE-2007-2447",
        service="smb",
        product="samba",
        version=None,
        port=139,
        module="exploit/multi/samba/usermap_script",
        required_options=["RHOSTS"],
        rank=100,
    ),

    # Drupalgeddon2
    VulhubExploitRule(
        rule_id="drupalgeddon2",
        scenario="drupal/CVE-2018-7600",
        source_lab="vulhub",
        cve="CVE-2018-7600",
        service="http",
        product="drupal",
        version=None,
        port=80,
        module="exploit/unix/webapp/drupal_drupalgeddon2",
        required_options=["RHOSTS"],
        rank=100,
    ),

# Struts2 RCE
VulhubExploitRule(
    rule_id="struts2_rce",
    scenario="struts2/s2-045",
    source_lab="vulhub",
    cve="CVE-2017-5638",
    service="http",
    product="struts",
    version=None,
    port=8080,
    module="exploit/multi/http/struts2_content_type_ognl",
    required_options=["RHOSTS"],
    default_options={
    "TARGETURI": "/"
},
    rank=100,
),

    # Tomcat Manager
    VulhubExploitRule(
        rule_id="tomcat_mgr",
        scenario="tomcat/manager",
        source_lab="vulhub",
        cve=None,
        service="http",
        product="apache tomcat",
        version=None,
        port=8080,
        module="exploit/multi/http/tomcat_mgr_upload",
        required_options=["RHOSTS", "USERNAME", "PASSWORD"],
        default_options={"TARGETURI": "/manager/html"},
        requires_approval=True,
        rank=80,
    ),

    # Grafana CVE-2021-43798
VulhubExploitRule(
    rule_id="grafana_2021_43798",
    scenario="grafana/CVE-2021-43798",
    source_lab="vulhub",
    cve="CVE-2021-43798",
    service="http",
    product="grafana",
    version=None,
    port=3000,
    module="auxiliary/scanner/http/grafana_plugin_traversal",
    required_options=["RHOSTS"],
    default_options={},
    rank=95,
    notes="Grafana arbitrary file read via directory traversal; commonly detected via nuclei grafana templates",
    tags=["grafana", "lfi", "http", "cve-2021-43798"],
),

]