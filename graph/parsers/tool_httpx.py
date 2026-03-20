from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
import subprocess
import time


@dataclass(frozen=True)
class HttpxPolicy:
    max_targets: int = 1000
    # Per-request timeout passed to httpx (-timeout flag, in seconds)
    request_timeout_s: int = 10
    # Follow redirects
    follow_redirects: bool = True


@dataclass
class HttpxRunResult:
    targets: List[str]
    args: List[str]
    exit_code: int
    started_at: float
    finished_at: float
    # Raw JSONL output — one JSON object per line, fed into parse_httpx
    stdout_jsonl: str
    stderr: str
    httpx_version: str


class HttpxTool:
    """
    Runs httpx against a list of URLs and returns the raw JSONL output.

    Multiple targets are passed via stdin (piped as newline-separated URLs),
    matching how httpx is typically used in pipelines:
        echo -e "http://target:80\nhttps://target:443" | httpx -json ...

    Flags used (from actions.py fingerprinting command):
        -json          one JSON object per line
        -tech-detect   detect technologies and versions
        -status-code   include HTTP status code
        -title         include page title
        -web-server    include web server header
        -silent        suppress banner output
    """

    def __init__(self, httpx_path: str = "httpx") -> None:
        self.httpx_path = httpx_path

    def _get_version(self) -> str:
        cp = subprocess.run(
            [self.httpx_path, "-version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        return (cp.stdout or cp.stderr or "").strip()

    def _validate(self, targets: List[str], policy: HttpxPolicy) -> None:
        if not targets:
            raise ValueError("targets must not be empty")
        if len(targets) > policy.max_targets:
            raise ValueError(f"Too many targets: {len(targets)} > {policy.max_targets}")

    def _build_args(self, policy: HttpxPolicy) -> List[str]:
        args = [
            self.httpx_path,
            "-json",
            "-tech-detect",
            "-status-code",
            "-title",
            "-web-server",
            "-silent",
            "-timeout", str(policy.request_timeout_s),
        ]
        if policy.follow_redirects:
            args.append("-follow-redirects")
        return args

    def run(
        self,
        targets: List[str],
        *,
        policy: Optional[HttpxPolicy] = None,
        timeout_s: int = 120,
    ) -> HttpxRunResult:
        policy = policy or HttpxPolicy()
        self._validate(targets, policy)

        httpx_version = self._get_version()
        args = self._build_args(policy)

        # Pass URLs via stdin — one per line
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

        return HttpxRunResult(
            targets=targets,
            args=args,
            exit_code=cp.returncode,
            started_at=started_at,
            finished_at=finished_at,
            stdout_jsonl=cp.stdout or "",
            stderr=cp.stderr or "",
            httpx_version=httpx_version,
        )
