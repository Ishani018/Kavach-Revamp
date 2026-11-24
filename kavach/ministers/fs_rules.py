"""What a call changes on disk, judged by where.

EXECUTOR's deny rules match dangerous command text. These rules ask a
different question: which paths does this call write, delete or re-permission,
whether through a file-writing tool or a shell command, and is that a place an
agent working on a project should be changing?

* Kavach's own controls (the hooks file, the hook script, its state, the
  variables that point the hook at the service, the service process): BLOCK.
  A monitor the agent can switch off is not a monitor.
* Account and login databases, and places code is run from automatically
  (cron, systemd, shell start-up files, git hooks, launch agents): BLOCK.
* Anywhere else under the operating system's own directories: ESCALATE. An
  administrator does this on purpose; a coding task rarely needs it.
* Project files that run a command without being asked (package.json
  lifecycle scripts, editor tasks that run when the folder opens), when the
  written text gives them a download-or-shell command: ESCALATE.
* A credential or a file that belongs to the machine (under /etc, /proc, a
  home dot-directory, ...) handed to a network client as its upload body:
  BLOCK. Such a path and an upload in the same script: ESCALATE.

Reading is not a change and never matches here. Shell variables assigned a
literal once are substituted first, so `p=/etc/group; rm "$p"` is seen as
`rm /etc/group`.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from typing import Any, List, Mapping, Optional, Tuple

from .. import toolshape
from .scan import MinisterScan

# ---- shell variable resolution ------------------------------------------------

_ASSIGN = re.compile(
    r"^[ \t]*(?:(?:local|export|declare(?:[ \t]+-\w+)*|readonly|typeset)[ \t]+)?"
    r"([A-Za-z_]\w*)=(?:'([^'\n]*)'|\"([^\"$`\\\n]*)\"|([^\s'\"$`;&|()<>\\]*))[ \t]*(?:;|$)", re.M)
_MAX_RESOLVE = 200_000


def resolve_shell_variables(command: str) -> str:
    """Replace $NAME / ${NAME} with its value when NAME is only ever assigned
    one literal. Anything assigned twice, or from an expansion, is left alone."""
    if len(command) > _MAX_RESOLVE or "=" not in command or "$" not in command:
        return command
    values: dict = {}
    conflicted = set()
    for m in _ASSIGN.finditer(command):
        name = m.group(1)
        value = next((g for g in m.groups()[1:] if g is not None), "")
        if name in values and values[name] != value:
            conflicted.add(name)
        values[name] = value
    # any other assignment form (from an expansion, read, for-loop variable) makes it unknown
    for m in re.finditer(r"(?:^|[\s;&|(])(?:for[ \t]+|read[ \t]+(?:-\w+[ \t]+)*)([A-Za-z_]\w*)", command):
        conflicted.add(m.group(1))
    for m in re.finditer(r"(?:^|[\s;&|(])([A-Za-z_]\w*)=", command):
        if m.group(1) not in values:
            conflicted.add(m.group(1))
    usable = {k: v for k, v in values.items() if k not in conflicted and "$" not in v}
    if not usable:
        return command

    def sub(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        return usable.get(name, m.group(0))

    out = command
    for _ in range(3):  # values may mention other resolved names only via literal text, so this converges fast
        new = re.sub(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", sub, out)
        if new == out:
            break
        out = new
    return out


# ---- paths --------------------------------------------------------------------

_HOME = re.compile(r"^(?:~|\$HOME|\$\{HOME\}|/root|/home/[^/]+|/Users/[^/]+)(?=/|$)")


def _norm(path: str) -> str:
    p = path.strip().strip("'\"")
    p = _HOME.sub("~", p)
    if p.startswith("/"):
        p = posixpath.normpath(p)
    elif p.startswith("~/"):
        p = "~/" + posixpath.normpath(p[2:])
    else:
        p = posixpath.normpath(p) if p else p
    return p


_SELF = re.compile(
    r"(?:^|/)\.github/hooks(?:/|$)|(?:^|/)kavach_vscode_hook\.py$|(?:^|/)\.kavach-vscode(?:/|$)"
    r"|(?:^|/)\.claude/settings(?:\.local)?\.json$|(?:^|/)\.kavach(?:/|$)", re.I)
_AUTH_OR_AUTORUN = re.compile(
    r"^/etc/(?:passwd-?|shadow-?|group-?|gshadow-?|sudoers(?:\.d(?:/.*)?)?|ssh(?:/.*)?|pam\.d(?:/.*)?|security(?:/.*)?"
    r"|ld\.so\.preload|ld\.so\.conf(?:\.d/.*)?|cron[^/]*(?:/.*)?|anacrontab|systemd(?:/.*)?|init\.d(?:/.*)?|rc\.local"
    r"|profile(?:\.d/.*)?|environment|bash\.bashrc|zsh/.*|hosts\.allow|hosts\.deny)$"
    r"|^/var/spool/cron(?:/.*)?$|^/(?:usr/)?lib/systemd/system(?:/.*)?$"
    r"|^~/\.ssh/(?:authorized_keys2?|config|rc)$"
    r"|^(?:~|/Library|/System/Library)/(?:Library/)?Launch(?:Agents|Daemons)(?:/.*)?$"
    r"|^~/\.config/(?:systemd/user|autostart)(?:/.*)?$", re.I)
_SHELL_STARTUP = re.compile(
    r"^~/\.(?:bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zshenv|zprofile|zlogin|kshrc|cshrc|tcshrc|inputrc)$"
    r"|^~/\.config/fish/(?:config\.fish|conf\.d/.*)$", re.I)
_GIT_HOOK = re.compile(r"(?:^|/)\.git/hooks/(?!.*\.sample$)[^/]+$|(?:^|/)\.husky/[^/_][^/]*$", re.I)
_SYSTEM = re.compile(
    r"^/(?:etc|bin|sbin|boot|lib|lib32|lib64|sys|proc|dev|usr/(?!local(?:/|$))[^/]*|var/(?:lib|log|spool|db)"
    r"|System|Library|private/etc|private/var/db)(?:/|$)", re.I)
_DEV_SINKS = re.compile(r"^/dev/(?:null|stdout|stderr|stdin|tty|fd/\d+|zero|urandom|random)$")
_SENSITIVE_READ = re.compile(
    r"^/etc/(?:passwd|shadow|gshadow|sudoers|ssh/.*|security/.*)$|^~/\.(?:ssh|aws|gnupg|kube|docker|azure|config/gcloud)(?:/.*)?$"
    r"|(?:^|/)\.env(?:\.[\w.-]+)?$|(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)$|^/proc/[^/]+/environ$|\.pem$|(?:^|/)\.netrc$|(?:^|/)\.npmrc$"
    r"|(?:^|/)credentials(?:\.json)?$", re.I)


def machine_or_secret(path: str) -> bool:
    """A credential, or a file that belongs to the machine rather than the
    project: sending one to a network address tells someone about this host."""
    p = _norm(path)
    return bool(_SENSITIVE_READ.search(p) or (_SYSTEM.match(p) and not _DEV_SINKS.match(p)) or re.match(r"^~/\.[\w-]", p))


def classify(path: str) -> Optional[Tuple[str, str]]:
    """(rule, verdict) for changing this path, or None."""
    p = _norm(path)
    if not p or _DEV_SINKS.match(p):
        return None
    if _SELF.search(p):
        return "kavach-control-write", "BLOCK"
    if _AUTH_OR_AUTORUN.match(p):
        return "auth-or-autorun-write", "BLOCK"
    if _SHELL_STARTUP.match(p):
        return "shell-startup-write", "BLOCK"
    if _GIT_HOOK.search(p):
        return "git-hook-write", "BLOCK"
    if _SYSTEM.match(p):
        return "system-path-write", "ESCALATE"
    return None


# ---- what a shell command changes ----------------------------------------------

_SEGMENT = re.compile(r"\|\||&&|[;\n|]|(?<![<>&\d])&(?![>&])")
_REDIRECT = re.compile(r"(?<![<\d&])(?:\d|&)?>{1,2}\|?\s*(\"[^\"\n]+\"|'[^'\n]+'|[^\s;&|<>()]+)")
_WRAPPERS = frozenset({"sudo", "doas", "env", "nohup", "time", "command", "exec", "nice", "ionice", "builtin"})
_ANY_OPERAND = frozenset({"rm", "rmdir", "unlink", "shred", "truncate", "chmod", "chown", "chgrp", "chattr",
                          "mv", "tee", "touch", "mkdir", "mkfs", "wipefs", "patch", "gzip", "gunzip", "xz"})
_LAST_OPERAND = frozenset({"cp", "install", "ln", "rsync", "scp"})


def _words(segment: str) -> List[str]:
    try:
        return shlex.split(segment, comments=True)
    except ValueError:
        return segment.split()


def mutated_paths(command: str) -> List[str]:
    out: List[str] = []
    for m in _REDIRECT.finditer(command):
        out.append(m.group(1))
    for segment in _SEGMENT.split(command):
        words = _words(_REDIRECT.sub(" ", segment))
        while words and (words[0] in _WRAPPERS or re.match(r"^[A-Za-z_]\w*=", words[0]) or words[0].startswith("-")):
            words = words[1:]
        if not words:
            continue
        name = words[0].rsplit("/", 1)[-1]
        operands = [w for w in words[1:] if not w.startswith("-")]
        if name in _ANY_OPERAND:
            out += operands[1:] if name in ("chmod", "chown", "chgrp", "chattr") and len(operands) > 1 else operands
        elif name in _LAST_OPERAND and len(operands) >= 2:
            out.append(operands[-1])
        elif name == "sed" and any(re.match(r"^-\w*i|^--in-place", w) for w in words[1:]):
            out += operands[1:]
        elif name == "dd":
            out += [w[3:] for w in words[1:] if w.startswith("of=")]
        elif name == "git" and "core.hooksPath" in words:
            out.append(".git/hooks/core.hooksPath")
        elif name in ("crontab",) and operands and operands[0] != "-l" and "-l" not in words:
            out.append("/var/spool/cron/crontabs/user")
    return out


_KILL_SERVICE = re.compile(
    r"\b(?:pkill|killall|kill)\b[^\n;|&]*\b(?:kavach|uvicorn)\b"
    r"|\b(?:lsof\b[^\n;&]*:?8088|fuser\b[^\n;&]*8088)[^\n;&]*\|\s*xargs\s+(?:-\S+\s+)*kill\b|\bfuser\s+-k\b[^\n;&]*8088", re.I)
_ENV_OVERRIDE = re.compile(
    r"(?:^|[\s;&|(])(?:(?:export|unset|declare(?:\s+-\w+)*|readonly)\s+KAVACH_[A-Z0-9_]+\b|KAVACH_[A-Z0-9_]+=)", re.M)
_UPLOAD_FLAG = r"(?:-d|--data(?:-\w+)?|-F|--form(?:-string)?|-T|--upload-file|--post-file|--body-file|--json)"
_NET_CLIENT = r"(?:curl|wget|http|https|httpie|xh|nc|ncat|netcat|socat|scp|sftp|ftp|rsync)"
_UPLOAD = re.compile(
    rf"\b{_NET_CLIENT}\b[^\n;|&]*\s({_UPLOAD_FLAG})(?:\s+|=)[\"']?([@<]?)([^\s;&|\"']+)", re.I)
_FILE_FLAGS = frozenset({"-t", "--upload-file", "--post-file", "--body-file"})
_HAS_UPLOAD = re.compile(rf"\b{_NET_CLIENT}\b[^\n;|&]*\s{_UPLOAD_FLAG}\b|\b(?:nc|ncat|netcat|socat)\b[^\n;|&]*\s\d{{2,5}}\b|/dev/tcp/", re.I)
_PATH_TOKEN = re.compile(r"(?<![\w.-])(?:~|\$HOME|/)[\w.@%+~/-]*|(?<![\w/.-])\.env(?:\.[\w.-]+)?\b")


def _scan(rule: str, verdict: str, why: str) -> MinisterScan:
    return MinisterScan(minister="EXECUTOR", verdict=verdict, confidence=1.0,
                        matched_id=f"EXECUTOR-FS:{rule}", matched_text=why,
                        matched_level="deterministic", source="path policy", retrieval_mode="deterministic")


def _autorun_content(path: str, content: str) -> Optional[str]:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    risky = r"(?:curl|wget|nc|ncat|bash|sh|zsh|powershell|pwsh|node\s+-e|python3?\s+-c|base64|eval)\b"
    if name == "package.json" and re.search(
            rf"\"(?:pre|post)?(?:install|prepare|prepack|postpack)\"\s*:\s*\"[^\"\n]*{risky}", content, re.I):
        return "package-lifecycle-script"
    if name == "tasks.json" and re.search(r"\"runOn\"\s*:\s*\"folderOpen\"", content, re.I):
        return "editor-autorun-task"
    return None


def check(tool: str, args: Optional[Mapping[str, Any]]) -> Optional[MinisterScan]:
    """The most serious path-rule hit for this call, or None."""
    hits: List[MinisterScan] = []
    written = toolshape.write_of(tool, args)
    if written is not None:
        path, content = written
        found = classify(path)
        if found:
            hits.append(_scan(found[0], found[1], f"file write to a protected location ({found[0]})"))
        autorun = _autorun_content(path, content)
        if autorun:
            hits.append(_scan(autorun, "ESCALATE", f"written file runs a command automatically ({autorun})"))
    command = toolshape.command_of(tool, args)
    if command is not None:
        resolved = resolve_shell_variables(command)
        for path in mutated_paths(resolved):
            found = classify(path)
            if found:
                hits.append(_scan(found[0], found[1], f"command changes a protected location ({found[0]})"))
        if _KILL_SERVICE.search(resolved):
            hits.append(_scan("kavach-service-kill", "BLOCK", "command stops the Kavach service"))
        if _ENV_OVERRIDE.search(resolved):
            hits.append(_scan("kavach-env-override", "BLOCK", "command changes a KAVACH_ setting"))
        for m in _UPLOAD.finditer(resolved):
            # `-d @file` and `-T file` send a file; `-d 'text'` sends the text itself
            names_a_file = bool(m.group(2)) or m.group(1).lower() in _FILE_FLAGS
            if names_a_file and machine_or_secret(m.group(3)):
                hits.append(_scan("sensitive-file-upload", "BLOCK", "a sensitive file is sent as an upload body"))
        if _HAS_UPLOAD.search(resolved) and any(machine_or_secret(t) for t in _PATH_TOKEN.findall(resolved)):
            hits.append(_scan("sensitive-path-with-upload", "ESCALATE",
                              "the same script names a sensitive file and sends data out"))
    if not hits:
        return None
    return next((h for h in hits if h.verdict == "BLOCK"), hits[0])
