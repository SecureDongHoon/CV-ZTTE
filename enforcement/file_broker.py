"""File Broker (spec §19, §60.12).

Mediates FILE_READ / FILE_WRITE / FILE_DELETE against a bounded workspace root
and defends against ``..`` traversal, symlink escape, mount escape, and path
substitution/races. Descriptor-based safe resolution is preferred (spec §19):
this reference resolves the real path, enforces containment within the workspace
root, opens the final component with ``O_NOFOLLOW`` to defeat a symlinked leaf,
and re-verifies containment on the opened descriptor to close the TOCTOU window.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.adapters.base import AdapterBinding
from cvztte.context.model import ObservationSource
from cvztte.errors import CVZTTEError, ErrorCode
from enforcement.common import (
    AuthorizedDecision,
    EnforcementBroker,
    ExecutionResult,
)

_OP_TO_ACTION = {
    "read": ActionType.FILE_READ,
    "write": ActionType.FILE_WRITE,
    "delete": ActionType.FILE_DELETE,
}


@dataclass(frozen=True)
class FileRequest:
    path: str
    operation: str  # read | write | delete
    content: bytes | None = None
    data_classification: DataClassification = DataClassification.INTERNAL


class FileBroker(EnforcementBroker):
    source = ObservationSource.FILE_BROKER
    audience = "file-broker-01"

    def __init__(self, workspace_root: str, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # The single bounded workspace root; everything outside is not directly
        # brokerable through this instance.
        self._root = os.path.realpath(workspace_root)

    def observe(self, request: FileRequest, binding: AdapterBinding) -> AgentAction:
        if request.operation not in _OP_TO_ACTION:
            raise CVZTTEError(
                ErrorCode.SCHEMA_INVALID,
                "unknown file operation",
                detail={"operation": request.operation},
            )
        return AgentAction(
            action_type=_OP_TO_ACTION[request.operation],
            target=request.path,
            operation=request.operation,
            resource=self._root,
            data_classification=request.data_classification,
        )

    def _safe_resolve(self, requested: str) -> str:
        """Resolve ``requested`` and confirm it stays within the workspace root.

        Rejects absolute paths, ``..`` traversal, and symlink/mount escape by
        comparing the fully realpath-resolved candidate against the root.
        """
        if os.path.isabs(requested):
            raise CVZTTEError(
                ErrorCode.FILE_PATH_ESCAPE, "absolute paths are not permitted"
            )
        candidate = os.path.realpath(os.path.join(self._root, requested))
        # Containment: candidate must be the root or strictly inside it.
        if candidate != self._root and not candidate.startswith(self._root + os.sep):
            raise CVZTTEError(
                ErrorCode.FILE_PATH_ESCAPE,
                "resolved path escapes the workspace root",
            )
        return candidate

    def _open_nofollow(self, path: str, flags: int, mode: int = 0o600) -> int:
        """Open with O_NOFOLLOW and re-verify containment on the descriptor."""
        try:
            fd = os.open(path, flags | os.O_NOFOLLOW, mode)
        except OSError as exc:
            # ELOOP => the final component is a symlink (escape attempt).
            raise CVZTTEError(
                ErrorCode.FILE_PATH_ESCAPE,
                "refusing to follow symlink at target",
                detail={"errno": exc.errno},
            ) from exc
        # Close the TOCTOU window: the opened inode's realpath must still be
        # contained. (/proc/self/fd resolves the real backing path.)
        try:
            real = os.path.realpath(f"/proc/self/fd/{fd}")
            if real != self._root and not real.startswith(self._root + os.sep):
                os.close(fd)
                raise CVZTTEError(
                    ErrorCode.FILE_PATH_ESCAPE, "opened path escapes workspace root"
                )
        except OSError:
            os.close(fd)
            raise CVZTTEError(
                ErrorCode.FILE_ACCESS_DENIED, "could not verify opened path"
            )
        return fd

    def _execute(
        self, action: AgentAction, decision: AuthorizedDecision, request: FileRequest
    ) -> ExecutionResult:
        path = self._safe_resolve(request.path)
        op = request.operation
        try:
            if op == "read":
                fd = self._open_nofollow(path, os.O_RDONLY)
                try:
                    data = os.read(fd, 64 * 1024 * 1024)
                finally:
                    os.close(fd)
                digest = "sha256:" + hashlib.sha256(data).hexdigest()
                return ExecutionResult(result_ref=path, result_hash=digest)
            if op == "write":
                content = request.content or b""
                fd = self._open_nofollow(
                    path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                )
                try:
                    os.write(fd, content)
                finally:
                    os.close(fd)
                digest = "sha256:" + hashlib.sha256(content).hexdigest()
                return ExecutionResult(result_ref=path, result_hash=digest)
            # delete
            os.unlink(path)
            return ExecutionResult(result_ref=path)
        except CVZTTEError:
            raise
        except FileNotFoundError as exc:
            raise CVZTTEError(ErrorCode.FILE_ACCESS_DENIED, "file not found") from exc
        except OSError as exc:
            raise CVZTTEError(
                ErrorCode.FILE_ACCESS_DENIED, "filesystem operation failed",
                detail={"errno": exc.errno},
            ) from exc
