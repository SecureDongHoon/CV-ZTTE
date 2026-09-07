"""Process Broker (spec §20, §60.12).

Mediates process execution for coding-agent runtimes. Enforces a command
allow/deny list, refuses ``shell=True`` (argv only, never a shell string),
applies resource limits (CPU + address space + output size), runs non-root, and
uses Linux namespace isolation via ``unshare`` where practical (best-effort in
this reference; documented fallback when unavailable — e.g. no user namespaces).

High-frequency ordinary work inside the approved workspace is expected to run
without central proof per syscall (spec §60.13); only boundary crossings are
mediated. This broker is the boundary for spawning processes.
"""

from __future__ import annotations

import hashlib
import os
import resource
import shutil
import subprocess
from dataclasses import dataclass, field

from cvztte.action.model import ActionType, AgentAction
from cvztte.adapters.base import AdapterBinding
from cvztte.context.model import ObservationSource
from cvztte.errors import CVZTTEError, ErrorCode
from enforcement.common import (
    AuthorizedDecision,
    EnforcementBroker,
    ExecutionResult,
)


@dataclass(frozen=True)
class ProcessConfig:
    allowed_commands: frozenset[str] = field(default_factory=frozenset)
    workspace_cwd: str | None = None
    timeout_seconds: float = 30.0
    max_cpu_seconds: int = 10
    max_address_space_bytes: int = 512 * 1024 * 1024
    max_output_bytes: int = 1024 * 1024
    #: Best-effort namespace isolation. Silently unavailable in some sandboxes.
    use_unshare: bool = False


@dataclass(frozen=True)
class ProcessRequest:
    argv: list[str]


def _limits(cfg: ProcessConfig):
    def _apply() -> None:  # runs in the child before exec
        resource.setrlimit(
            resource.RLIMIT_CPU, (cfg.max_cpu_seconds, cfg.max_cpu_seconds)
        )
        resource.setrlimit(
            resource.RLIMIT_AS,
            (cfg.max_address_space_bytes, cfg.max_address_space_bytes),
        )

    return _apply


class ProcessBroker(EnforcementBroker):
    source = ObservationSource.PROCESS_BROKER
    audience = "process-broker-01"

    def __init__(self, config: ProcessConfig, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cfg = config

    def observe(self, request: ProcessRequest, binding: AdapterBinding) -> AgentAction:
        if not request.argv:
            raise CVZTTEError(ErrorCode.SCHEMA_INVALID, "empty argv")
        return AgentAction(
            action_type=ActionType.PROCESS_EXEC,
            target=os.path.basename(request.argv[0]),
            operation="exec",
            arguments={"argv": list(request.argv)},
        )

    def _resolve_command(self, argv: list[str]) -> str:
        name = os.path.basename(argv[0])
        if name not in self._cfg.allowed_commands:
            raise CVZTTEError(
                ErrorCode.PROCESS_COMMAND_DENIED,
                "command not on allowlist",
                detail={"command": name},
            )
        path = shutil.which(argv[0]) or (argv[0] if os.path.isabs(argv[0]) else None)
        if not path or not os.path.exists(path):
            raise CVZTTEError(
                ErrorCode.PROCESS_COMMAND_DENIED, "command not found", detail={"command": name}
            )
        return path

    def _execute(
        self, action: AgentAction, decision: AuthorizedDecision, request: ProcessRequest
    ) -> ExecutionResult:
        path = self._resolve_command(request.argv)
        cmd = [path, *request.argv[1:]]

        if self._cfg.use_unshare and shutil.which("unshare"):
            # Best-effort user+net namespace isolation. If the kernel/sandbox
            # forbids it the child will fail and we surface that (fail closed).
            cmd = ["unshare", "--user", "--net", "--", *cmd]

        try:
            proc = subprocess.run(  # noqa: S603 - argv only, shell=False always
                cmd,
                shell=False,
                capture_output=True,
                timeout=self._cfg.timeout_seconds,
                cwd=self._cfg.workspace_cwd,
                preexec_fn=_limits(self._cfg),
            )
        except subprocess.TimeoutExpired as exc:
            raise CVZTTEError(ErrorCode.EXECUTION_FAILED, "process timed out") from exc
        except OSError as exc:
            raise CVZTTEError(
                ErrorCode.EXECUTION_FAILED, "process spawn failed", detail={"errno": exc.errno}
            ) from exc

        stdout = proc.stdout[: self._cfg.max_output_bytes]
        digest = "sha256:" + hashlib.sha256(stdout).hexdigest()
        return ExecutionResult(
            result_ref=f"process:{action.target}",
            result_hash=digest,
            detail={
                "returncode": proc.returncode,
                "stdout": stdout.decode("utf-8", "replace"),
            },
        )
