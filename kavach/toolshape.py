"""What kind of tool is this call? Shared by the ministers and the coordinator.

Hosts name the same thing differently: VS Code's terminal tool is
`runInTerminal` / `run_in_terminal`, Claude Code's is `Bash`, other harnesses
use `bash`, `shell` or `execute_command`. The ministers must reach the same
verdict whatever the host calls it, so the question "is this a terminal call?"
and "is this a file write, of what, to where?" are answered here once.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Optional, Tuple

_TERMINAL_NAMES = frozenset({
    "bash", "sh", "zsh", "shell", "terminal", "runinterminal", "runterminal", "runterminalcmd",
    "runterminalcommand", "executecommand", "runcommand", "execcommand", "runshellcommand",
    "shellcommand", "localshell", "exec", "runbash",
})
_WRITE_NAMES = frozenset({
    "createfile", "writefile", "write", "edit", "multiedit", "editfile", "replacestringinfile",
    "inserteditintofile", "applypatch", "strreplaceeditor", "strreplacebasededittool", "createorupdatefile",
    "writetofile", "replaceinfile", "notebookedit", "editnotebookfile", "appendfile", "savefile",
})
COMMAND_KEYS = ("command", "cmd", "script", "code")
_PATH_KEYS = ("filePath", "file_path", "path", "filename", "file", "target_file", "notebook_path", "uri")
_CONTENT_KEYS = ("content", "contents", "text", "new_string", "newString", "new_str", "file_text",
                 "code", "patch", "input", "new_source", "insert_text")


def normalize(tool_name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (tool_name or "").lower())


def is_terminal(tool_name: str) -> bool:
    return normalize(tool_name) in _TERMINAL_NAMES


def shell_dialect(tool_name: str) -> Optional[str]:
    """The grammar to parse this tool's command with, or None when it is not a
    POSIX terminal tool. `sh` stays `sh`; every other terminal name is parsed
    as bash, which covers the POSIX subset the rules look at."""
    name = normalize(tool_name)
    if name == "sh":
        return "sh"
    return "bash" if name in _TERMINAL_NAMES else None


def command_of(tool_name: str, arguments: Optional[Mapping[str, Any]]) -> Optional[str]:
    if not is_terminal(tool_name):
        return None
    for key in COMMAND_KEYS:
        value = (arguments or {}).get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def is_write(tool_name: str) -> bool:
    return normalize(tool_name) in _WRITE_NAMES


def write_of(tool_name: str, arguments: Optional[Mapping[str, Any]]) -> Optional[Tuple[str, str]]:
    """(path, content) for a file-writing call. Content is "" when the tool
    edits in place and only the new text is unknown."""
    if not is_write(tool_name):
        return None
    args = arguments or {}
    path = next((args[k] for k in _PATH_KEYS if isinstance(args.get(k), str) and args[k].strip()), None)
    if path is None:
        return None
    parts = [args[k] for k in _CONTENT_KEYS if isinstance(args.get(k), str)]
    edits = args.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, Mapping):
                parts += [edit[k] for k in _CONTENT_KEYS if isinstance(edit.get(k), str)]
    return path, "\n".join(parts)
