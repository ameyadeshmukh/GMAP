from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
import subprocess
import time


@dataclass(frozen=True)
class NucleiPolicy:
    max_targets: int = 1000
    severity: str = "critical,high,medium"
    # Technology-specific template tags (e.g. ["apache", "wordpress", "tomcat"])
    tags: List[str] = field(default_factory=list)
    rate_limit: int = 150
    concurrency: int = 25
    # Per-request timeout passed to nuclei (-timeout flag, in seconds)
    request_timeout_s: int = 10


@dataclass
class NucleiRunResult:
    targets: List[str]
    args: List[str]
    exit_code: int
    started_at: float
    finished_at: float
    # Raw JSONL output — one JSON object per finding, fed into parse_nuclei
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
        -json            one JSON object per finding
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
        """
        Run nuclei with a raw command string (for retry_command from orchestrator).
        """
        args = command.strip().split()
        if args[0] == "nuclei":
            args[0] = self.nuclei_path

        # Ensure JSON output
        if "-json" not in args:
            args.append("-json")

        # Extract targets if provided via -u flag
        targets = []
        if "-u" in args:
            idx = args.index("-u")
            targets = [args[idx + 1]]
            args.pop(idx)
            args.pop(idx)
        elif "-l" in args:
            idx = args.index("-l")
            targets = [args[idx + 1]]
            args.pop(idx)
            args.pop(idx)

        stdin_input = "\n".join(targets) if targets else ""
        nuclei_version = self._get_version()

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

    def _validate(self, targets: List[str], policy: NucleiPolicy) -> None:
        if not targets:
            raise ValueError("targets must not be empty")
        if len(targets) > policy.max_targets:
            raise ValueError(f"Too many targets: {len(targets)} > {policy.max_targets}")

    def _build_args(self, policy: NucleiPolicy) -> List[str]:
        args = [
            self.nuclei_path,
            "-json",
            "-silent",
            "-no-color",
            "-severity", policy.severity,
            "-rate-limit", str(policy.rate_limit),
            "-concurrency", str(policy.concurrency),
            "-timeout", str(policy.request_timeout_s),
        ]

        if policy.tags:
            args.extend(["-tags", ",".join(policy.tags)])

        return args

    def run(
        self,
        targets: List[str],
        *,
        policy: Optional[NucleiPolicy] = None,
        timeout_s: int = 600,
    ) -> NucleiRunResult:
        policy = policy or NucleiPolicy()
        self._validate(targets, policy)

        nuclei_version = self._get_version()
        args = self._build_args(policy)

        stdin_input = "\n".join(targets)

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
