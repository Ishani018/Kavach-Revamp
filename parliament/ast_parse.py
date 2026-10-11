"""parliament/ast_parse.py
=========================

Real grammar-based parsing for the E1 (network-fetch-to-disk) and V1/V2
(credential-path-read/search) primitives, replacing struct_parse.py's
lightweight tokenizer where a genuine parser is available for the shell
dialect in question.

Reuses struct_parse.py's own role-classification predicates
(_is_credential_path, _URL_RE, _REMOTE_HOST_RE, _WRITE_FLAG_RE,
_CRED_GLOB_RE) unchanged -- the upgrade here is WHERE the candidate word
list comes from (a real AST's command-argument nodes, not a naive
whitespace/quote tokenizer that can't tell code from data), not a new
classification scheme.

Dialect routing (confirmed empirically, not assumed):
  - bash / sh: bashlex (pure-Python POSIX shell parser, pip-installed).
    Produces a real AST distinguishing command words from heredoc bodies,
    comments, and string-literal contents.
  - powershell: Windows PowerShell 5.1's built-in
    [System.Management.Automation.Language.Parser] (no separate install --
    confirmed present on this machine), invoked via a short PowerShell
    subprocess that walks CommandAst nodes and emits their argument text
    as JSON.
  - command_prompt (cmd.exe): NEITHER parser applies. Confirmed via direct
    test: bashlex.parse() raises ParsingError on real cmd.exe syntax
    (`for /l %i in (...) do ...`) -- cmd.exe's batch-file grammar is a
    different language, not a shell dialect either library understands.
    91 of the 519-case corpus's cases use this tool. Falls back to
    struct_parse.py's tokenizer, honestly, not silently mislabeled as
    AST-backed.
  - everything else (ruby/python/manual/etc, ~19 cases): falls back to
    struct_parse.py's tokenizer -- no real general-purpose-language AST
    was investigated for these tonight; out of scope for this pass.

A parser failure on a THEORETICALLY-supported dialect (malformed input,
an edge case bashlex/the PS parser doesn't handle) falls back to the
tokenizer too, never raises up to the caller -- same fail-open discipline
as struct_parse.py itself.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field

from . import struct_parse as sp

try:
    import bashlex
    _BASHLEX_AVAILABLE = True
except ImportError:
    _BASHLEX_AVAILABLE = False

# Dialects with a real, empirically-confirmed-working AST tonight.
_BASHLEX_DIALECTS = frozenset({"sh", "bash"})
_POWERSHELL_DIALECTS = frozenset({"powershell"})

# cmd.exe and everything else stay on struct_parse.py's tokenizer --
# confirmed no real parser applies (see module docstring).
_NO_AST_DIALECTS = frozenset({"command_prompt"})


@dataclass
class AstExtractResult:
    words: list[str] = field(default_factory=list)
    used_ast: bool = False
    dialect: str | None = None


def _bashlex_words(cmd: str) -> list[str] | None:
    """Walks a bashlex AST, returning only words that are real command
    arguments -- never heredoc body content, comments, or (per bashlex's
    own parse of quoted strings) the literal text of an unrelated
    command's string argument. Returns None on any parse failure (falls
    back to the tokenizer, never raises)."""
    try:
        trees = bashlex.parse(cmd)
    except Exception:
        return None

    words: list[str] = []

    def walk(node) -> None:
        kind = getattr(node, "kind", None)
        if kind == "word":
            words.append(node.word)
        # Recurse into command lists (pipelines, `;`/`&&`-joined lists,
        # subshells) so a multi-command line is fully covered -- but NOT
        # into a HeredocNode's body, which bashlex already keeps out of
        # the `parts` tree as heredoc.value rather than a WordNode/
        # CommandNode, so simply not special-casing it here is correct:
        # heredoc content structurally never reaches this walk at all.
        for attr in ("parts", "list", "command", "commands"):
            children = getattr(node, attr, None)
            if children is None:
                continue
            if isinstance(children, list):
                for c in children:
                    walk(c)
            else:
                walk(children)

    for tree in trees:
        walk(tree)
    return words


# Cached path to a working PowerShell executable, resolved once.
_PS_EXE: str | None = None
_PS_EXE_CHECKED = False


def _resolve_ps_exe() -> str | None:
    global _PS_EXE, _PS_EXE_CHECKED
    if _PS_EXE_CHECKED:
        return _PS_EXE
    _PS_EXE_CHECKED = True
    for candidate in ("powershell.exe", "pwsh"):
        try:
            r = subprocess.run(
                [candidate, "-NoProfile", "-NonInteractive", "-Command", "'ok'"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                _PS_EXE = candidate
                return _PS_EXE
        except Exception:
            continue
    return None


# The PS-side script: parses $env:AST_PARSE_INPUT via the real language
# parser, walks BOTH CommandAst nodes (`Verb-Noun arg1 arg2` calls) AND
# InvokeMemberExpressionAst nodes (`(...).Method(arg1, arg2)` calls --
# confirmed necessary via direct test: (New-Object Net.WebClient).
# DownloadFile('url','path') parses as a ParenExpressionAst wrapping a
# CommandAst for `New-Object`, with .DownloadFile(...) as a SEPARATE
# InvokeMemberExpressionAst whose arguments are NOT CommandElements of
# any CommandAst -- a CommandAst-only walk misses every .NET-style
# method-call fetch entirely, e.g. WebClient.DownloadFile/DownloadString,
# which is exactly the shape several real corpus attack cases use).
# Never touches commented-out or never-executed text -- confirmed via
# direct test: a `#`-commented line produces zero matches from either
# node type, since PowerShell's parser drops it before the AST exists.
# Reads the command from an environment variable rather than an argv/
# stdin string to sidestep quoting hazards entirely.
_PS_WALK_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$src = $env:AST_PARSE_INPUT
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errors)
$words = New-Object System.Collections.Generic.List[string]
$commands = $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]}, $true)
foreach ($c in $commands) {
    foreach ($el in $c.CommandElements) {
        $words.Add($el.Extent.Text)
    }
}
$invokes = $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]}, $true)
foreach ($inv in $invokes) {
    $words.Add($inv.Expression.Extent.Text)
    $words.Add($inv.Member.Extent.Text)
    foreach ($arg in $inv.Arguments) {
        $words.Add($arg.Extent.Text)
    }
}
$words | ConvertTo-Json -Compress
"""


def _powershell_words(cmd: str) -> list[str] | None:
    """Real PowerShell-AST-backed word extraction. Returns None on any
    failure (unresolvable powershell.exe, timeout, parse error) -- falls
    back to the tokenizer, never raises."""
    exe = _resolve_ps_exe()
    if exe is None:
        return None
    try:
        import os
        env = dict(os.environ)
        env["AST_PARSE_INPUT"] = cmd
        r = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command", _PS_WALK_SCRIPT],
            capture_output=True, text=True, timeout=15, env=env,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return []
        data = json.loads(r.stdout)
        if isinstance(data, str):
            return [data]
        if isinstance(data, list):
            return [str(x) for x in data]
        return []
    except Exception:
        return None


def extract_words(cmd: str, dialect: str | None) -> AstExtractResult:
    """Dispatch by dialect to a real AST where one is confirmed to apply,
    otherwise fall back to struct_parse.py's tokenizer. `dialect` is the
    wire-format tool name (e.g. "sh", "powershell", "command_prompt") --
    the caller (check_vault/check_executor) already has this from the
    parsed call, so no re-detection/guessing happens here."""
    if dialect in _BASHLEX_DIALECTS and _BASHLEX_AVAILABLE:
        words = _bashlex_words(cmd)
        if words is not None:
            return AstExtractResult(words=words, used_ast=True, dialect=dialect)
    elif dialect in _POWERSHELL_DIALECTS:
        words = _powershell_words(cmd)
        if words is not None:
            return AstExtractResult(words=words, used_ast=True, dialect=dialect)

    # Fallback: struct_parse.py's tokenizer (also covers command_prompt
    # and every other dialect -- confirmed no real parser applies).
    return AstExtractResult(words=sp._shell_tokenize(cmd), used_ast=False, dialect=dialect)


def is_network_fetch_to_disk(cmd: str, dialect: str | None = None) -> tuple[bool, str | None, bool]:
    """AST-backed E1 check where available. Returns (matched, evidence,
    used_ast) -- the third element lets callers/tests distinguish an
    AST-confirmed hit from a tokenizer-fallback hit."""
    extracted = extract_words(cmd, dialect)
    r = sp.StructResult()
    has_disk_write_method = False
    for tok in extracted.words:
        if sp._URL_RE.search(tok):
            r.urls.append(sp._URL_RE.search(tok).group(0))
        if sp._REMOTE_HOST_RE.search(tok):
            r.remote_hosts.append(tok)
        if sp._WRITE_FLAG_RE.match(tok):
            r.write_destinations.append("<next-arg>")
        if sp._is_credential_path(tok):
            r.credential_paths.append(tok)
        if sp._DISK_WRITE_METHOD_RE.match(tok):
            has_disk_write_method = True
        m = sp._PATH_RE.search(tok)
        if m and not sp._URL_RE.search(tok):
            r.filepaths.append(tok)

    # Write-destination flags name the NEXT token as their value; re-walk
    # with index awareness to capture it (the loop above only detects the
    # flag itself). Mirrors struct_parse.py's own two-pass approach.
    for i, tok in enumerate(extracted.words):
        if sp._WRITE_FLAG_RE.match(tok) and i + 1 < len(extracted.words):
            r.write_destinations = [w for w in r.write_destinations if w != "<next-arg>"]
            r.write_destinations.append(extracted.words[i + 1])
    # Redirect operators don't appear as separate "words" in bashlex's
    # command.parts (they're RedirectNodes, not WordNodes) -- detected
    # via the raw command text as struct_parse.py already does, since a
    # redirect's PRESENCE (not its target word) is what has_redirect_write
    # cares about, and this is unambiguous even from raw text.
    r.has_redirect_write = bool(sp._REDIRECT_RE.search(cmd))

    has_source = bool(r.urls or r.remote_hosts)
    if not has_source:
        return False, None, extracted.used_ast
    has_dest = bool(r.write_destinations) or r.has_redirect_write or has_disk_write_method
    if not has_dest and r.remote_hosts:
        if any(not sp._URL_RE.search(p) and "@" not in p for p in r.filepaths):
            has_dest = True
    if has_source and has_dest:
        # Payload-staging gate for URL-sourced fetches ONLY (E1 FP fix) --
        # identical discriminator to struct_parse.is_network_fetch_to_disk():
        # a bare data fetch-to-disk with no pipe-to-interpreter and no
        # executable-extension target is benign and must not fire. Remote-host
        # (scp) staging is not gated, matching the tokenizer path exactly.
        if sp._needs_staging_gate(cmd, r) and not sp._url_fetch_is_payload_staging(cmd, r):
            return False, None, extracted.used_ast
        src = (r.urls or r.remote_hosts)[0]
        dst = (r.write_destinations or ["<redirect>"])[0] if (r.write_destinations or r.has_redirect_write) else "<local-path>"
        return True, f"fetch {src!r} -> disk {dst!r}", extracted.used_ast
    return False, None, extracted.used_ast


def has_credential_path(cmd: str, dialect: str | None = None) -> tuple[bool, str | None, bool]:
    """AST-backed V1/V2 check where available. Returns (matched, evidence,
    used_ast)."""
    extracted = extract_words(cmd, dialect)
    for tok in extracted.words:
        if sp._is_credential_path(tok):
            return True, f"credential path {tok!r}", extracted.used_ast
    for gm in sp._CRED_GLOB_RE.finditer(cmd):
        return True, f"credential glob {gm.group(0)!r}", extracted.used_ast
    return False, None, extracted.used_ast
