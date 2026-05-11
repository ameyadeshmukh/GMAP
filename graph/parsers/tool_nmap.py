from __future__ import annotations

from dataclasses import dataclass
from typing import List, Literal, Optional
import subprocess
import time

# Args that can be used to run different nmap commands args dependent on whats needed.
NmapIntent = Literal["HOST_DISCOVERY", "TCP_TOP_PORTS", "TCP_ALL_PORTS"]


@dataclass(frozen=True)
class ScanPolicy: # Scan policy just for the intital process. Created to be changed or the same when called in another program file
    max_targets: int = 256
    default_top_ports: int = 1000
    allow_all_ports: bool = False
    timing_template: str = "T3"
    disable_dns: bool = True
    tcp_scan_type: str = "-sT"  


@dataclass 
class NmapRunResult:
    intent: NmapIntent
    targets: List[str]
    args: List[str]
    exit_code: int
    started_at: float
    finished_at: float
    stdout_xml: str
    stderr: str
    nmap_version: str


class NmapTool:
    def __init__(self, nmap_path: str = "nmap") -> None:
        self.nmap_path = nmap_path

    def _get_version(self) -> str:
        cp = subprocess.run(
            [self.nmap_path, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        return (cp.stdout or cp.stderr or "").strip()
        
    def run_raw(self, command: str, timeout_s: int = 300):
    # take out leading nmap if the llm put it in
        args = command.strip().split()
        if args[0] == "nmap":
            args[0] = self.nmap_path

        if "-oX" not in args:
            args.extend(["-oX", "-"])

        nmap_version = self._get_version()
        started_at = time.time()
        cp = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_s,
        )
        finished_at = time.time()

        return NmapRunResult(
            intent="TCP_ALL_PORTS", 
            targets=[],
            args=args,
            exit_code=cp.returncode,
            started_at=started_at,
            finished_at=finished_at,
            stdout_xml=cp.stdout or "",
            stderr=cp.stderr or "",
            nmap_version=nmap_version,
        )

# Error condtions 
    def _validate(self, intent: NmapIntent, targets: List[str], policy: ScanPolicy) -> None:
        if not targets:
            raise ValueError("targets must not be empty")
        if len(targets) > policy.max_targets:
            raise ValueError(f"Too many targets: {len(targets)} > {policy.max_targets}")
        if intent == "TCP_ALL_PORTS" and not policy.allow_all_ports:
            raise ValueError("TCP_ALL_PORTS is disabled by policy")

    def _build_args(
        self,
        intent: NmapIntent,
        targets: List[str],
        policy: ScanPolicy,
        top_ports: int,
    ) -> List[str]:
        args = [self.nmap_path, "--reason", "-oX", "-"]

        if policy.disable_dns:
            args.append("-n")

        args.append(f"-{policy.timing_template}")
# Args differences betwen the three options
        if intent == "HOST_DISCOVERY":
            return [*args, "-sn", *targets]

        if intent == "TCP_TOP_PORTS":
            return [*args, policy.tcp_scan_type, "--top-ports", str(top_ports), *targets]

        if intent == "TCP_ALL_PORTS":
            return [*args, policy.tcp_scan_type, "-p-", *targets]

        raise ValueError(f"Unknown intent: {intent}")

# Validates the inputs and runs the commands in order to get the results to normalize them
    def run(
        self,
        intent: NmapIntent,
        targets: List[str],
        *,
        policy: Optional[ScanPolicy] = None,
        top_ports: Optional[int] = None,
        timeout_s: int = 300,
    ):
        policy = policy or ScanPolicy()
        self._validate(intent, targets, policy)

        effective_top_ports = top_ports if top_ports is not None else policy.default_top_ports
        nmap_version = self._get_version()
        args = self._build_args(intent, targets, policy, effective_top_ports)

        started_at = time.time()
        cp = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_s,
        )
        finished_at = time.time()

        return NmapRunResult(
            intent=intent,
            targets=targets,
            args=args,
            exit_code=cp.returncode,
            started_at=started_at,
            finished_at=finished_at,
            stdout_xml=cp.stdout or "",
            stderr=cp.stderr or "",
            nmap_version=nmap_version,
        )