"""Scripts this session wrote, so running one is judged by what it contains.

Without this, an agent can put any payload in a file with one call and run it
with `bash task.sh` in the next: the second call shows the ministers nothing.
The coordinator records what write tools put where (per agent tree, bounded),
and when a terminal call executes one of those files it hands the ministers the
command together with the file's content, in the form the same code would have
had inline. Resolution only ever adds text to inspect.
"""

from __future__ import annotations

import re
import shlex
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

from . import toolshape

MAX_FILES = 64
MAX_BYTES = 256_000
_SEGMENT = re.compile(r"\|\||&&|[;\n|&]")
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "source", "."})
_INTERPRETERS = re.compile(r"^(python(\d+(\.\d+)?)?|pypy\d*|node|nodejs|bun|deno|ruby|perl\d*|php\d*|lua|rscript)$", re.I)
_WRAPPERS = frozenset({"sudo", "env", "nohup", "time", "exec", "command", "nice", "timeout", "xargs", "run"})


class WrittenFiles:
    def __init__(self) -> None:
        self._by_domain: Dict[str, "OrderedDict[str, str]"] = {}

    def record(self, domain: str, path: str, content: str) -> None:
        if not content or len(content) > MAX_BYTES:
            return
        files = self._by_domain.setdefault(domain, OrderedDict())
        key = _norm(path)
        files.pop(key, None)
        files[key] = content
        while len(files) > MAX_FILES:
            files.popitem(last=False)

    def record_heredoc_writes(self, domain: str, command: str) -> None:
        """`cat > x.sh <<'EOF' ... EOF` writes a script through the shell."""
        for m in _HEREDOC_WRITE.finditer(command):
            self.record(domain, m.group("path") or m.group("path2"), m.group("body") or m.group("body2") or "")

    def resolve(self, domain: str, command: str) -> List[Tuple[str, str, str]]:
        """[(path, runner, content)] for every recorded file the command executes."""
        files = self._by_domain.get(domain)
        if not files:
            return []
        found: List[Tuple[str, str, str]] = []
        for segment in _SEGMENT.split(command):
            try:
                words = shlex.split(segment, comments=True)
            except ValueError:
                words = segment.split()
            while words and (words[0] in _WRAPPERS or "=" in words[0] and not words[0].startswith(("/", "."))):
                words = words[1:]
            if not words:
                continue
            head = words[0].rsplit("/", 1)[-1]
            if head in _SHELLS or _INTERPRETERS.match(head):
                runner = "bash" if head in _SHELLS else head
                candidates = [w for w in words[1:] if not w.startswith("-")][:1]
            else:
                runner, candidates = "", [words[0]]
            for word in candidates:
                content = _lookup(files, word)
                if content is not None:
                    found.append((word, runner or _runner_for(word, content), content))
        return found


_HEREDOC_WRITE = re.compile(
    r"(?:cat|tee)\b[^\n|;&]*?>{1,2}\s*(?P<path>[^\s<>|;&]+)[^\n]*?<<-?\s*['\"]?(?P<tag>\w+)['\"]?[^\n]*\n(?P<body>.*?)\n\s*(?P=tag)\b"
    r"|(?:cat|tee)\b[^\n|;&]*?<<-?\s*['\"]?(?P<tag2>\w+)['\"]?\s*>{1,2}\s*(?P<path2>[^\s<>|;&]+)[^\n]*\n(?P<body2>.*?)\n\s*(?P=tag2)\b",
    re.S,
)


def _norm(path: str) -> str:
    return re.sub(r"/+", "/", path.strip().strip("'\"")).removeprefix("./")


def _lookup(files: "OrderedDict[str, str]", word: str) -> Optional[str]:
    key = _norm(word)
    if key in files:
        return files[key]
    if not key.startswith(("/", "~")):  # relative: match a recorded path that ends with it
        for path, content in reversed(files.items()):
            if path.endswith("/" + key) or path.rsplit("/", 1)[-1] == key:
                return content
    return None


def _runner_for(path: str, content: str) -> str:
    first = content.lstrip().split("\n", 1)[0]
    if first.startswith("#!"):
        name = first[2:].split()[-1].rsplit("/", 1)[-1] if first[2:].split() else ""
        if _INTERPRETERS.match(name):
            return name
        return "bash"
    return "python3" if path.endswith(".py") else "node" if path.endswith((".js", ".mjs")) else "bash"


def expand(command: str, resolved: List[Tuple[str, str, str]]) -> str:
    """The command plus, for each executed file, its content as inline code."""
    out = [command]
    for i, (_path, runner, content) in enumerate(resolved):
        if runner == "bash":
            out.append(content)
        else:
            out.append(f"{runner} - <<'RESOLVED_SCRIPT_{i}'\n{content}\nRESOLVED_SCRIPT_{i}")
    return "\n".join(out)


def command_key(arguments) -> Optional[str]:
    for key in toolshape.COMMAND_KEYS:
        if isinstance((arguments or {}).get(key), str) and arguments[key].strip():
            return key
    return None
