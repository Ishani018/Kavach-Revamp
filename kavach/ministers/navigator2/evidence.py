"""
kavach/ministers/navigator2/evidence.py
==========================================

Component 6 -- Evidence Modules.

Reuses the repository's EXISTING, already-working AST integration
(kavach/ministers/ast_parse.py -- bashlex for sh/bash, the native PowerShell
parser for powershell) rather than adding a second shell-parsing dependency.
See docs/navigator2-research.md "What was explicitly not done" for why
tree-sitter-bash was not separately evaluated.

Parsing proves syntax, not intent. An unsupported or malformed input is
reported with coverage="indeterminate", never silently treated as safe (feeds
policy.py's POL-007).
"""

from __future__ import annotations

import ast
import os
import re
import shlex
from typing import Dict, List, Optional

from .. import ast_parse
from ...schemas import MinisterResult, ToolCall
from .schemas import EvidenceFinding

try:
    import bashlex
    _BASHLEX_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only if the dependency is missing
    _BASHLEX_AVAILABLE = False

# Dialects ast_parse.py confirms it can genuinely AST-parse.
_SHELL_DIALECTS = frozenset({"sh", "bash"})
_POWERSHELL_DIALECTS = frozenset({"powershell"})
# VS Code Local's terminal tool name is an adapter name, not a shell dialect.
_TERMINAL_WRAPPER_NAMES = frozenset({"run_in_terminal", "runinterminal", "run_terminal"})
# zsh and dash use a POSIX-compatible parser approximation, never claimed as full coverage.
_POSIX_APPROXIMATION_DIALECTS = frozenset({"zsh", "dash"})
# Fast path for unquoted, simple portable commands.
_SIMPLE_PORTABLE_COMMAND_RE = re.compile(r"^[A-Za-z0-9_./:@%+,-]+(?:[ \t]+[A-Za-z0-9_./:@%+,-]+)*$")

def _has_only_supported_shell_syntax(command: str) -> bool:
    """Accept the constrained POSIX syntax subset covered by the parser.

    This separates syntax coverage from command safety. Compound command-list
    operators (&& and ;) are permitted when bashlex parsed the complete input.
    Expansions, substitutions, redirects, pipelines, globs, subshells, and
    background execution remain indeterminate in the zsh/dash approximation.
    """
    quote = None
    escaped = False
    i = 0
    while i < len(command):
        char = command[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if quote == "'":
            if char == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if char == "\\":
                escaped = True
            elif char == '"':
                quote = None
            elif char in "$`":
                return False
            i += 1
            continue
        if char == "\\":
            escaped = True
        elif char == "'":
            quote = "'"
        elif char == '"':
            quote = '"'
        elif char in "$`<>|*?[]{}()\r\n":
            return False
        elif char == "&":
            # Logical AND is supported; single & (background execution) is not.
            if i + 1 >= len(command) or command[i + 1] != "&":
                return False
            i += 1
        # A semicolon is a parsed command-list operator, not an unknown shell
        # feature. Whether a command is risky is left to the policy pipeline.
        i += 1
    return quote is None and not escaped


def _python_inline_code_is_static_print(words: List[str]) -> bool:
    """Recognize only literal-only Python -c print statements as harmless syntax.

    A shell AST cannot prove the effects of embedded interpreter code. Imports,
    attribute calls, assignments, dynamic values, and all other code stay
    indeterminate even if the outer shell command parses cleanly.
    """
    if not words:
        return False
    executable = words[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if not re.fullmatch(r"python(?:3(?:\.\d+)?)?", executable):
        return True
    if "-c" not in words[1:]:
        return True
    code_index = words.index("-c") + 1
    if code_index >= len(words):
        return False
    try:
        parsed = ast.parse(words[code_index])
    except (SyntaxError, ValueError, TypeError):
        return False
    if not parsed.body:
        return False
    for statement in parsed.body:
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            return False
        call = statement.value
        if not isinstance(call.func, ast.Name) or call.func.id != "print" or call.keywords:
            return False
        if not all(isinstance(argument, ast.Constant) for argument in call.args):
            return False
    return True


def _is_constrained_terminal_command(command: str) -> bool:
    """Check terminal syntax coverage, not whether the command is safe.

    The AST parser must already have parsed this command. Supported command-list
    syntax is covered generically without hardcoding executable names. Dynamic
    or unsupported shell features remain indeterminate. Inline Python is narrower:
    only literal-only print() statements qualify.
    """
    stripped = command.strip()
    if _SIMPLE_PORTABLE_COMMAND_RE.fullmatch(stripped):
        return True
    if not stripped or not _has_only_supported_shell_syntax(stripped):
        return False
    try:
        words = shlex.split(stripped, posix=True)
    except ValueError:
        return False
    return bool(words) and _python_inline_code_is_static_print(words)

_DECODE_COMMANDS = re.compile(r"^(base64|base32|base16|xxd)$", re.IGNORECASE)
_DECODE_FLAG = re.compile(r"^-?-?d(ecode)?$", re.IGNORECASE)
_EXEC_SINKS = frozenset({"eval", "bash", "sh", "source", ".", "perl", "python", "python3", "node", "ruby"})


class EvidenceModule:
    """Protocol (duck-typed, no ABC needed for a 2-method interface)."""

    name: str = "base"

    def analyze(self, call: ToolCall) -> List[EvidenceFinding]:
        raise NotImplementedError


def _configured_terminal_dialect() -> Optional[str]:
    """Resolve terminal-wrapper shell from local runtime configuration.

    KAVACH_TERMINAL_DIALECT is the explicit override. SHELL is a fallback for
    macOS/Linux sessions started from the user's configured shell. Unknown
    values stay unknown so the evidence layer fails closed instead of guessing.
    """
    raw = os.environ.get("KAVACH_TERMINAL_DIALECT") or os.environ.get("SHELL")
    if not isinstance(raw, str) or not raw.strip():
        return None
    name = raw.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name in {"bash", "bash.exe"}:
        return "bash"
    if name in {"sh", "sh.exe"}:
        return "sh"
    if name in {"dash", "dash.exe"}:
        return "dash"
    if name in {"zsh", "zsh.exe"}:
        return "zsh"
    if name in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        return "powershell"
    if name in {"cmd", "cmd.exe", "command.com"}:
        return "command_prompt"
    return name or None


def _parser_dialect(dialect: Optional[str]) -> Optional[str]:
    """Choose a parser only when the configured shell has a known approximation."""
    if dialect == "zsh":
        return "bash"  # bashlex handles the common POSIX-compatible subset
    if dialect == "dash":
        return "sh"
    return dialect


def _command_text_and_dialect(call: ToolCall) -> Optional[tuple]:
    """Best-effort extraction of (command_text, dialect) from common argument
    shapes. Returns None if the call doesn't look like a shell/script
    invocation at all -- that is not itself suspicious, just not this
    module's business."""
    args = call.arguments or {}
    tool_name = call.tool_name.strip().lower().replace("-", "_")
    if tool_name in (_SHELL_DIALECTS | _POWERSHELL_DIALECTS | {"command_prompt"}):
        dialect = tool_name
    elif tool_name in _TERMINAL_WRAPPER_NAMES:
        # run_in_terminal is a host wrapper. Treating its name as a dialect
        # incorrectly marks every command indeterminate and triggers POL-007.
        dialect = _configured_terminal_dialect()
    else:
        dialect = None
    for key in ("command", "cmd", "script", "code"):
        v = args.get(key)
        if isinstance(v, str) and v.strip():
            return v, dialect
    return None


class ShellEvidenceModule(EvidenceModule):
    name = "shell_ast"

    def analyze(self, call: ToolCall) -> List[EvidenceFinding]:
        found = _command_text_and_dialect(call)
        if found is None:
            return []
        cmd, dialect = found
        parser_dialect = _parser_dialect(dialect)
        extracted = ast_parse.extract_words(cmd, parser_dialect)
        if extracted.used_ast and dialect in _POSIX_APPROXIMATION_DIALECTS:
            # bashlex is only a POSIX-compatible approximation for zsh/dash.
            # The AST must parse the command. Supported command-list syntax is
            # covered generically, while expansions/substitutions, redirections,
            # pipelines and other unsupported features remain indeterminate.
            # Inline Python -c code is narrower: only literal-only print()
            # expressions qualify; other code remains indeterminate.
            if _is_constrained_terminal_command(cmd):
                coverage = "partial"
                claim = (
                    f"parsed using {parser_dialect} AST as a POSIX-compatible approximation "
                    f"for terminal shell {dialect} ({len(extracted.words)} argument words); "
                    "constrained terminal syntax subset"
                )
                confidence = 0.65
            else:
                coverage = "indeterminate"
                claim = (
                    f"terminal shell {dialect} command uses syntax outside the simple portable subset; "
                    "shell-specific or compound semantics remain unverified"
                )
                confidence = 0.0
        elif extracted.used_ast:
            coverage = "full"
            claim = f"parsed via real {dialect} grammar ({len(extracted.words)} argument words)"
            confidence = 1.0
        elif dialect in (_SHELL_DIALECTS | _POWERSHELL_DIALECTS):
            coverage = "partial"
            claim = f"AST parse of a theoretically-supported dialect ({dialect}) failed; fell back to tokenizer"
            confidence = 0.3
        else:
            coverage = "indeterminate"
            claim = f"no reliable AST coverage for configured dialect {dialect!r}; tokenizer-only, unsupported-syntax risk not ruled out"
            confidence = 0.0
        return [EvidenceFinding(module=self.name, claim=claim, confidence=confidence, coverage=coverage,
                                 supporting={"dialect": dialect, "parser_dialect": parser_dialect, "word_count": len(extracted.words)})]


def _walk_assignments_and_sinks(trees) -> tuple:
    """Returns (assigned_decoders: dict[varname -> decode evidence str],
    sinks: list[(sink_name, referenced_vars: set[str])])."""
    assigned_decoders: Dict[str, str] = {}
    sinks: List[tuple] = []

    def command_first_word(node) -> Optional[str]:
        for part in getattr(node, "parts", None) or []:
            if getattr(part, "kind", None) == "word":
                return part.word
        return None

    def contains_decode_command(node) -> Optional[str]:
        """Search a subtree (a commandsubstitution's contents) for a command
        whose first word is a decode tool invoked with a decode flag."""
        found = None

        def rec(n):
            nonlocal found
            kind = getattr(n, "kind", None)
            if kind == "command":
                words = [p.word for p in (getattr(n, "parts", None) or []) if getattr(p, "kind", None) == "word"]
                if words and _DECODE_COMMANDS.match(words[0]):
                    if any(_DECODE_FLAG.match(w) for w in words[1:]) or words[0].lower() in ("xxd",):
                        found = " ".join(words)
                elif words and words[0] in ("python", "python3") and any("b64decode" in w or "a85decode" in w or "b32decode" in w for w in words):
                    found = " ".join(words)
            for attr in ("parts", "list", "command", "commands"):
                children = getattr(n, attr, None)
                if children is None:
                    continue
                if isinstance(children, list):
                    for c in children:
                        rec(c)
                else:
                    rec(children)

        rec(node)
        return found

    def walk(node, depth=0):
        kind = getattr(node, "kind", None)
        if kind == "assignment" and isinstance(getattr(node, "word", None), str) and "=" in node.word:
            varname = node.word.split("=", 1)[0]
            decode_evidence = contains_decode_command(node)
            if decode_evidence:
                assigned_decoders[varname] = decode_evidence
        elif kind == "command":
            first = command_first_word(node)
            if first in _EXEC_SINKS:
                referenced: set = set()
                for part in getattr(node, "parts", None) or []:
                    w = getattr(part, "word", None)
                    if isinstance(w, str):
                        m = re.findall(r"\$\{?(\w+)\}?", w)
                        referenced.update(m)
                if referenced:
                    sinks.append((first, referenced))
        for attr in ("parts", "list", "command", "commands"):
            children = getattr(node, attr, None)
            if children is None:
                continue
            if isinstance(children, list):
                for c in children:
                    walk(c, depth + 1)
            else:
                walk(children, depth + 1)

    for tree in trees:
        walk(tree)
    return assigned_decoders, sinks


class DecodeExecutionEvidenceModule(EvidenceModule):
    """AST-based, single-hop, intra-command variable resolution for
    decode-then-execute data flows (see docs/navigator2-architecture.md SS8).
    Does NOT replace EXECUTOR's own regex-based base64-decode-then-exec rule
    (prefilters.py) -- this is additional structural evidence, scoped to
    NAVIGATOR 2.0's trajectory reasoning, not a competing EXECUTOR rule.

    Explicit limitation: resolution is one hop and intra-command only. A
    decoder assigned in one tool call and executed in a LATER call is not
    resolved here (that is a cross-call case; reported as coverage="partial",
    never silently claimed solved)."""

    name = "decode_execution_ast"

    def analyze(self, call: ToolCall) -> List[EvidenceFinding]:
        found = _command_text_and_dialect(call)
        if found is None:
            return []
        cmd, dialect = found
        if dialect not in (_SHELL_DIALECTS | _POSIX_APPROXIMATION_DIALECTS) or not _BASHLEX_AVAILABLE:
            return []  # out of scope for this module; ShellEvidenceModule reports unknown/unsupported dialect coverage
        try:
            # zsh/dash use bashlex only as a conservative common-syntax approximation.
            trees = bashlex.parse(cmd)
        except Exception:
            return [EvidenceFinding(
                module=self.name, claim="bash parse failed; decode-execution flow not resolvable",
                confidence=0.0, coverage="indeterminate", supporting={"dialect": dialect},
            )]

        assigned_decoders, sinks = _walk_assignments_and_sinks(trees)
        findings: List[EvidenceFinding] = []

        resolved_vars = set()
        for sink_name, referenced in sinks:
            hit_vars = referenced & assigned_decoders.keys()
            if hit_vars:
                resolved_vars |= hit_vars
                for v in hit_vars:
                    findings.append(EvidenceFinding(
                        module=self.name,
                        claim=f"decode-then-execute: ${v} assigned from {assigned_decoders[v]!r}, then executed via {sink_name!r}",
                        confidence=0.9,
                        coverage="full",
                        supporting={"variable": v, "sink": sink_name, "decoder": assigned_decoders[v]},
                    ))

        # Decoders that were assigned but never seen reaching a sink IN THIS
        # command: report as partial evidence (decode happened; execution
        # destination not confirmed here -- may be a later call, may be
        # benign storage/display). Never claimed as a confirmed attack.
        for v, decoder in assigned_decoders.items():
            if v not in resolved_vars:
                findings.append(EvidenceFinding(
                    module=self.name,
                    claim=f"${v} assigned from a decode operation ({decoder!r}); no execution sink for it found in this same call",
                    confidence=0.2,
                    coverage="partial",
                    supporting={"variable": v, "decoder": decoder},
                ))
        return findings


_SPECIALIST_NAMES = ("VAULT", "EXECUTOR", "CHANNEL", "NAVIGATOR")


class MinisterFindingsAdapter:
    """Wraps already-computed legacy MinisterResults into EvidenceFindings.
    The legacy-NAVIGATOR one is explicitly tagged as a supporting signal
    only, per the task brief: 'do not treat duplicated semantic alerts as
    independent proof.'"""

    name = "minister_findings_adapter"

    @staticmethod
    def adapt(legacy_results: Dict[str, MinisterResult]) -> List[EvidenceFinding]:
        out: List[EvidenceFinding] = []
        for name in _SPECIALIST_NAMES:
            r = legacy_results.get(name)
            if r is None:
                continue
            module = "legacy_navigator_semantic" if name == "NAVIGATOR" else f"specialist_minister:{name}"
            claim = f"{name} returned {r.verdict}"
            if name == "NAVIGATOR":
                claim += " (supporting anomaly signal only, not independent proof)"
            out.append(EvidenceFinding(
                module=module, claim=claim, confidence=float(r.confidence or 0.0),
                coverage="full", supporting={"matched_id": r.matched_id},
            ))
        return out


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s'\"|;>]+")


def extract_destinations_from_text(text: str) -> List[str]:
    """Heuristic email/URL-shaped string extraction from arbitrary text.
    Shared by extract_destinations() (this call's own ARGUMENTS -- used by
    POL-001, the proven-exfil policy, which must only look at what THIS
    action actually does) and core.py's contract-revision-attempt detector
    (which scans untrusted CONTENT -- tool_output/user_instruction text --
    for a destination it is trying to induce, a narrower and separate use)."""
    found = set(_EMAIL_RE.findall(text)) | set(_URL_RE.findall(text))
    return sorted(found)


def extract_destinations(call: ToolCall) -> List[str]:
    """Heuristic extraction of email/URL-shaped destination strings from this
    call's own arguments. Documented as heuristic/partial coverage -- not a
    replacement for CHANNEL's own destination analysis, just a concrete
    string for POL-001 to compare against contract.approved_destinations
    (which CHANNEL has no access to)."""
    text_parts: List[str] = []
    for v in (call.arguments or {}).values():
        if isinstance(v, str):
            text_parts.append(v)
    blob = "\n".join(text_parts)
    return extract_destinations_from_text(blob)


def run_all(call: ToolCall, legacy_results: Optional[Dict[str, MinisterResult]] = None,
            modules: Optional[List[EvidenceModule]] = None) -> List[EvidenceFinding]:
    modules = modules if modules is not None else [ShellEvidenceModule(), DecodeExecutionEvidenceModule()]
    findings: List[EvidenceFinding] = []
    for m in modules:
        try:
            findings.extend(m.analyze(call))
        except Exception as e:  # an evidence module must never crash the pipeline or fail open silently
            findings.append(EvidenceFinding(
                module=getattr(m, "name", type(m).__name__),
                claim=f"evidence module raised {type(e).__name__}; treated as indeterminate",
                confidence=0.0, coverage="indeterminate",
            ))
    if legacy_results:
        findings.extend(MinisterFindingsAdapter.adapt(legacy_results))
    return findings
