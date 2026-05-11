from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
import subprocess
import time


@dataclass(frozen=True)
class NucleiPolicy:
    max_targets: int = 1000
    severity: str = "critical,high,medium"
    tags: List[str] = field(default_factory=list)
    rate_limit: int = 150
    concurrency: int = 25
    request_timeout_s: int = 10
    cve_templates: bool = False  # run all templates by default


@dataclass
class NucleiRunResult:
    targets: List[str]
    args: List[str]
    exit_code: int
    started_at: float
    finished_at: float
    stdout_jsonl: str
    stderr: str
    nuclei_version: str


class NucleiTool:
    """
    Runs nuclei against a list of URLs and returns the raw JSONL output.

    Targets are passed via stdin (piped as newline-separated URLs),
    matching pipeline usage:
        echo -e "http://target:80\\nhttps://target:443" | nuclei -json ...

    Flags used (from actions.py vuln_detection command):
        -jsonl            one JSON object per finding
        -severity        filter by severity levels
        -silent          suppress banner output
        -no-color        disable ANSI color codes in output
    """

    def __init__(self, nuclei_path: str = "nuclei") -> None:
        self.nuclei_path = nuclei_path

    def _get_version(self) -> str:
        cp = subprocess.run(
            [self.nuclei_path, "-version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        return (cp.stdout or cp.stderr or "").strip()

    def run_raw(self, command: str, timeout_s: int = 600) -> NucleiRunResult:
    # if command contains a pipe, run as shell command
        if "|" in command:
            nuclei_version = self._get_version()
            started_at = time.time()
            cp = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_s,
            )
            finished_at = time.time()
            return NucleiRunResult(
                targets=[],
                args=[command],
                exit_code=cp.returncode,
                started_at=started_at,
                finished_at=finished_at,
                stdout_jsonl=cp.stdout or "",
                stderr=cp.stderr or "",
                nuclei_version=nuclei_version,
            )
        args = command.strip().split()
        if args[0] == "nuclei":
            args[0] = self.nuclei_path
        if "-jsonl" not in args:
            args.append("-jsonl")

        # DO NOT extract -u, leave targets in args as-is
        nuclei_version = self._get_version()
        started_at = time.time()
        cp = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_s,
        )
        finished_at = time.time()
        return NucleiRunResult(
            targets=[],
            args=args,
            exit_code=cp.returncode,
            started_at=started_at,
            finished_at=finished_at,
            stdout_jsonl=cp.stdout or "",
            stderr=cp.stderr or "",
            nuclei_version=nuclei_version,
        )

    def _validate(self, targets: List[str], policy: NucleiPolicy) -> None:
        if not targets:
            raise ValueError("targets must not be empty")
        if len(targets) > policy.max_targets:
            raise ValueError(f"Too many targets: {len(targets)} > {policy.max_targets}")

    def _build_args(self, policy: NucleiPolicy, targets: List[str]) -> List[str]:
        args = [
            self.nuclei_path,
            "-jsonl",
            "-no-color",
            "-severity", policy.severity,
            "-rate-limit", str(policy.rate_limit),
            "-concurrency", str(policy.concurrency),
            "-timeout", str(policy.request_timeout_s),
        ]
        if policy.cve_templates:
            args.extend(["-t", "http/cves/"])
        if policy.tags:
            args.extend(["-tags", ",".join(policy.tags)])

        # add targets
        if len(targets) == 1:
            args.extend(["-u", targets[0]])
        else:
            args.extend(["-l", "-"])  # read from stdin

        return args

    def run(self, targets, *, policy=None, timeout_s=600):
        policy = policy or NucleiPolicy()
        self._validate(targets, policy)

        nuclei_version = self._get_version()
        args = self._build_args(policy, targets)  # ← pass targets

        # only use stdin if passing via -l -
        stdin_input = "\n".join(targets) if len(targets) > 1 else None

        started_at = time.time()
        cp = subprocess.run(
            args,
            input=stdin_input,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_s,
        )

        finished_at = time.time()

        return NucleiRunResult(
            targets=targets,
            args=args,
            exit_code=cp.returncode,
            started_at=started_at,
            finished_at=finished_at,
            stdout_jsonl=cp.stdout or "",
            stderr=cp.stderr or "",
            nuclei_version=nuclei_version,
        )
