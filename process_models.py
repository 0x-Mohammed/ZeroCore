"""
ZeroCore Agent — Process Domain Models
Extends the base domain with process attribution types.
ProcessContext carries the full kernel-level process identity
for every file or exec event.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ProcessEventType(str, Enum):
    FILE_WRITE      = "vfs_write"
    FILE_CREATE     = "file_create"
    FILE_DELETE     = "file_delete"
    FILE_RENAME     = "file_rename"
    PROCESS_EXEC    = "execve"
    NETWORK_CONNECT = "network_connect"


class ProcessContext(BaseModel):
    """
    Full process attribution context emitted by the kernel bridge.
    Attached to SecurityEvents to answer: WHO modified WHAT and HOW.

    Example (from the eBPF probe):
        File Modified:  /etc/passwd
        Modified By:    PID: 4122
        Process:        python3
        Parent PID:     3891
        User:           root (uid=0)
        Command:        python3 exploit.py
    """
    pid:           int   = Field(..., description="Process ID of the writing process")
    ppid:          int   = Field(..., description="Parent process ID")
    uid:           int   = Field(..., description="User ID (0 = root)")
    gid:           int   = Field(..., description="Group ID")
    process_name:  str   = Field(..., description="Process comm name (e.g. 'python3')")
    file_path:     str   = Field(..., description="Absolute file path affected")
    command_line:  str   = Field(default="", description="Full command line or argv")
    event_type:    ProcessEventType
    source:        str   = Field(default="ebpf", description="'ebpf' | 'etw' | 'sysmon'")
    raw_timestamp: str   = Field(default="", description="ISO timestamp from kernel bridge")
    extra:         Dict[str, Any] = Field(default_factory=dict, description="Platform-specific extras")

    model_config = {"frozen": True}

    @property
    def is_root(self) -> bool:
        return self.uid == 0

    @property
    def is_suspicious_exec(self) -> bool:
        """
        Heuristic: Python/Perl/Bash spawned directly as a write actor
        in a sensitive path is almost always worth HIGH severity.
        """
        suspicious_interpreters = {
            "python", "python3", "python2",
            "perl", "ruby", "php",
            "bash", "sh", "zsh", "dash",
            "nc", "netcat", "ncat",
            "curl", "wget",
        }
        name = self.process_name.lower().split("/")[-1]
        return name in suspicious_interpreters

    def format_attribution(self) -> str:
        """
        Human-readable attribution block — used in SecurityEvent.description
        and API responses.

        Example output:
            Modified By: PID 4122 | python3 (uid=0) | CMD: python3 exploit.py
        """
        parts = [
            f"PID {self.pid}",
            f"{self.process_name} (uid={self.uid})",
        ]
        if self.ppid:
            parts.append(f"ppid={self.ppid}")
        if self.command_line:
            cmd = self.command_line[:80] + "..." if len(self.command_line) > 80 else self.command_line
            parts.append(f"CMD: {cmd}")
        return " | ".join(parts)

    def to_event_metadata(self) -> Dict[str, Any]:
        """Serialize to dict suitable for SecurityEvent.metadata injection."""
        return {
            "process_attribution": {
                "pid":          self.pid,
                "ppid":         self.ppid,
                "uid":          self.uid,
                "gid":          self.gid,
                "process_name": self.process_name,
                "command_line": self.command_line,
                "source":       self.source,
                "is_root":      self.is_root,
                "is_suspicious_exec": self.is_suspicious_exec,
            }
        }
