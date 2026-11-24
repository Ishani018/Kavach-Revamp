"""
kavach/ministers/navigator2/shell_coverage.py
================================================

Can Kavach see everything a terminal command will run?

This answers a *visibility* question, not a safety one: whether a command is
dangerous is decided by EXECUTOR's rules and NAVIGATOR's policies. When the
answer is "no", the evidence layer reports coverage="indeterminate" and
POL-007 escalates, so uncertainty never turns into permission.

The analysis walks the parse tree bashlex already builds. It is structural:
there are no lists of safe commands and no exact command strings. A construct
is covered when its semantics are fully determined by the text Kavach sees:

* command lists (`;`, `&&`, `||`) and pipelines: every command is visible.
* redirections to literal targets.
* command and process substitution: the inner command is visible and is
  analyzed by the same rules (recursively).
* inline code handed to another interpreter (`bash -c`, `python3 -c`,
  `node -e`, ...): the nested program is analyzed in its own language. Shell
  code recurses; Python code is covered only when it has no effects beyond
  computing values and printing them (see `python_is_side_effect_free`);
  languages Kavach cannot parse are not covered.

* control flow (if/for/while/until, `{ }` and `( )` groups, function
  definitions): every command in every branch and body is in the text and is
  analyzed like any other.
* here-documents and here-strings: the text is visible. When the command
  reading it is an interpreter with no script operand (`bash <<EOF`,
  `python3 - <<EOF`) it is a program and is analyzed in that language;
  otherwise it is input data for a visible command.

Not covered: background jobs (`&`), `eval` of anything but a literal, shell
constructs the parser does not model (`case`, `select`, arithmetic `for`), and
a command name computed at runtime (`$(curl x)`, `$CMD args`), which runs code
Kavach cannot see. For shells parsed by approximation (zsh and dash use
bashlex's POSIX grammar), the zsh-only forms that execute code are also not
covered: parameter flags such as `${(e)var}` and glob qualifiers such as
`*(e:cmd:)`. Plain `$VAR` and `*.py` mean the same there as in POSIX.

The interpreter table below is knowledge about *languages* (which flag
introduces inline code, and in which language), not a list of trusted
programs: a recognized interpreter makes coverage harder to get, never easier.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from ..ast_parse import unquote_heredoc_delimiters

try:
    import bashlex
    _BASHLEX = True
except ImportError:  # pragma: no cover
    _BASHLEX = False

# runner basename pattern -> (inline-code options, inline-code subcommands, language)
_INLINE_RUNNERS: List[Tuple[re.Pattern, Tuple[str, ...], Tuple[str, ...], str]] = [
    (re.compile(r"^(bash|sh)$"), ("c",), (), "shell:real"),
    (re.compile(r"^(zsh|dash)$"), ("c",), (), "shell:approx"),
    (re.compile(r"^(ksh|mksh|fish|tcsh|csh|busybox)$"), ("c",), (), "unparsed:shell"),
    (re.compile(r"^(python(\d+(\.\d+)?)?|pypy\d*)$"), ("c",), (), "python"),
    (re.compile(r"^(node|nodejs|bun)$"), ("e", "p", "eval", "print"), (), "unparsed:javascript"),
    (re.compile(r"^deno$"), (), ("eval",), "unparsed:javascript"),
    (re.compile(r"^(ruby|jruby)$"), ("e",), (), "unparsed:ruby"),
    (re.compile(r"^perl\d*$"), ("e",), (), "unparsed:perl"),
    (re.compile(r"^php\d*$"), ("r",), (), "unparsed:php"),
    (re.compile(r"^(lua|luajit|rscript|osascript)$", re.IGNORECASE), ("e",), (), "unparsed:script"),
    (re.compile(r"^(pwsh|powershell)(\.exe)?$", re.IGNORECASE),
     ("c", "command", "encodedcommand", "e", "ec", "enc"), (), "unparsed:powershell"),
    (re.compile(r"^cmd(\.exe)?$", re.IGNORECASE), (), ("/c", "/k"), "unparsed:cmd"),
]
_SHORT_CLUSTER = re.compile(r"^-[A-Za-z]{2,3}$")

_ALLOWED_OPERATORS = frozenset({";", "&&", "||", "\n"})
_ALLOWED_PIPES = frozenset({"|", "|&"})
_CONTROL_FLOW = frozenset({"compound", "if", "for", "while", "until", "function"})
_GLOB_CHARS = frozenset("*?[")
_ZSH_PARAMETER_FLAGS = re.compile(r"\$\{\s*[(=~^]")


@dataclass
class Coverage:
    covered: bool = True
    reasons: List[str] = field(default_factory=list)
    nested: List[str] = field(default_factory=list)   # languages of nested programs that were analyzed

    def fail(self, reason: str) -> None:
        self.covered = False
        if reason not in self.reasons:
            self.reasons.append(reason)


def analyze(command: str, *, approximation: bool, _depth: int = 0) -> Optional[Coverage]:
    """Coverage for a shell command, or None if it does not parse at all."""
    if not _BASHLEX:
        return None
    # bashlex rejects a quoted here-document delimiter (<<'EOF'). Quoting only
    # turns expansion off inside the body, so parsing it unquoted is the
    # stricter reading: any $(...) in the body is then analyzed, not ignored.
    command = unquote_heredoc_delimiters(command)
    try:
        trees = bashlex.parse(command)
    except Exception:
        return None
    cov = Coverage()
    if _depth > 4:
        cov.fail("nested code deeper than 4 levels")
        return cov
    for tree in trees:
        _walk(tree, command, cov, approximation, _depth)
    return cov


def _walk(node, source: str, cov: Coverage, approx: bool, depth: int) -> None:
    kind = node.kind
    if kind == "list":
        for part in node.parts:
            if part.kind == "operator":
                if part.op == "&":
                    cov.fail("background execution (&)")
                elif part.op not in _ALLOWED_OPERATORS:
                    cov.fail(f"unsupported operator {part.op!r}")
            else:
                _walk(part, source, cov, approx, depth)
    elif kind == "pipeline":
        for part in node.parts:
            if part.kind == "pipe":
                if part.pipe not in _ALLOWED_PIPES:
                    cov.fail(f"unsupported pipe {part.pipe!r}")
            else:
                _walk(part, source, cov, approx, depth)
    elif kind == "command":
        _command(node, source, cov, approx, depth)
    elif kind in _CONTROL_FLOW:
        # if/for/while/until, { } and ( ) groups, function definitions: the
        # grammar is only structure, and every command in every branch and body
        # is in the text, so each is analyzed like any other command.
        for part in (getattr(node, "list", None) or getattr(node, "parts", None) or []):
            if part.kind == "reservedword":
                continue
            if part.kind == "word":
                _word(part, source, cov, approx, depth)
            elif part.kind == "redirect":
                _redirect(part, None, source, cov, approx, depth)
            else:
                _walk(part, source, cov, approx, depth)
    else:
        cov.fail("unsupported shell construct (" + kind + ")")


def _command(node, source: str, cov: Coverage, approx: bool, depth: int) -> None:
    words: List[str] = []
    redirects = []
    for part in node.parts:
        if part.kind == "word":
            if not words and any(p.kind != "tilde" for p in (getattr(part, "parts", None) or [])):
                # `$(curl x)` or `$CMD` as the command name runs whatever the
                # expansion produces: code Kavach cannot see, like eval.
                cov.fail("command name computed at runtime")
            _word(part, source, cov, approx, depth)
            words.append(part.word)
        elif part.kind == "assignment":
            _word(part, source, cov, approx, depth)
        elif part.kind == "redirect":
            redirects.append(part)
        else:
            cov.fail("unsupported command part (" + part.kind + ")")
    for part in redirects:
        _redirect(part, words, source, cov, approx, depth)
    _nested_code(words, node, cov, approx, depth)


def _stdin_language(words: Optional[List[str]]) -> Optional[str]:
    """The language a command reads from standard input as a program, if any:
    `bash <<EOF`, `python3 - <<EOF`, `sh -s <<EOF`. A runner given a script
    operand reads that script, so its standard input is data."""
    for i, word in enumerate(words or []):
        name = _basename(word)
        for pattern, options, subcommands, language in _INLINE_RUNNERS:
            if not pattern.match(name):
                continue
            if _inline_code(words, i, options, subcommands) is not None:
                return None
            operands = [w for w in words[i + 1:] if not w.startswith("-") or w == "-"]
            return language if not operands or operands[0] == "-" else None
        if word and not word.startswith("-") and "=" not in word:
            return None  # only a leading runner (after env-style assignments) reads the program
    return None


def _redirect(part, words: Optional[List[str]], source: str, cov: Coverage, approx: bool, depth: int) -> None:
    heredoc = getattr(part, "heredoc", None)
    is_here = heredoc is not None or part.type in ("<<", "<<-", "<<<")
    output = getattr(part, "output", None)
    if not is_here:
        if output is not None and not isinstance(output, int):
            _word(output, source, cov, approx, depth)
        return
    # A here-document's text is in the command. It is a program only when the
    # command reading it is an interpreter with no script operand; then it is
    # analyzed in that language, exactly like `-c CODE`. Otherwise it is input
    # data for a command that is itself visible.
    if heredoc is not None:
        body = getattr(heredoc, "value", None)
    else:
        body = getattr(output, "word", None) if output is not None and not isinstance(output, int) else None
        if output is not None and not isinstance(output, int):
            _word(output, source, cov, approx, depth)
    language = _stdin_language(words)
    if language is None:
        return
    if body is None:
        cov.fail("here-document whose text could not be read")
        return
    cov.nested.append(language)
    if language == "shell:real":
        _nested_shell(body, cov, False, depth)
    elif language == "shell:approx":
        _nested_shell(body, cov, True, depth)
    elif language == "python":
        if not python_is_side_effect_free(body):
            cov.fail("Python on standard input with effects beyond computing and printing values")
    else:
        cov.fail(language.split(":", 1)[1] + " code on standard input Kavach cannot parse")


def _word(node, source: str, cov: Coverage, approx: bool, depth: int) -> None:
    for part in getattr(node, "parts", None) or []:
        if part.kind == "parameter":
            # Plain $VAR / ${VAR} / ${VAR:-x} mean the same in zsh and dash as in
            # POSIX. zsh parameter flags, ${(e)var} above all, can run code.
            if approx and _ZSH_PARAMETER_FLAGS.search(source[node.pos[0]:node.pos[1]]):
                cov.fail("zsh parameter flags under an approximated shell grammar")
        elif part.kind in ("commandsubstitution", "processsubstitution"):
            inner = getattr(part, "command", None)
            if inner is None:
                cov.fail("substitution without a parsed command")
            else:
                _walk(inner, source, cov, approx, depth)
        elif part.kind == "tilde":
            continue
        else:
            cov.fail("unsupported word expansion (" + part.kind + ")")
    if approx and _has_glob_qualifier(source[node.pos[0]:node.pos[1]]):
        cov.fail("zsh glob qualifier under an approximated shell grammar")


def _has_glob_qualifier(raw: str) -> bool:
    """An unquoted glob followed by `(`: zsh glob qualifiers such as
    `*(e:cmd:)` run code. A plain `*.py` means the same as in POSIX."""
    quote, escaped, seen_glob = None, False, False
    for ch in raw:
        if escaped:
            escaped = False
        elif ch == "\\" and quote != "'":
            escaped = True
        elif quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch in _GLOB_CHARS:
            seen_glob = True
        elif ch == "(" and seen_glob:
            return True
    return False


def _basename(word: str) -> str:
    return word.replace("\\", "/").rsplit("/", 1)[-1]


def _inline_code(words: List[str], index: int, options: Tuple[str, ...],
                 subcommands: Tuple[str, ...]) -> Optional[str]:
    """The inline program passed to the runner at words[index], if any.

    Every later word is scanned, not just the leading options: stopping at the
    first operand would let `python3 -W ignore -c CODE` hide CODE. A false
    match (a script argument that looks like the flag) only adds analysis."""
    for j in range(index + 1, len(words)):
        w = words[j]
        if w.lower() in subcommands:
            return " ".join(words[j + 1:])
        if w.startswith("-") and w != "-":
            opt = w.lstrip("-").lower()
            if opt in options or (_SHORT_CLUSTER.match(w) and w[-1].lower() in options):
                return words[j + 1] if j + 1 < len(words) else ""
    return None


def _nested_code(words: List[str], node, cov: Coverage, approx: bool, depth: int) -> None:
    if words and _basename(words[0]) == "eval":
        literal = all(not getattr(p, "parts", None) for p in node.parts if p.kind == "word")
        if not literal:
            cov.fail("eval of dynamically built code")
        else:
            _nested_shell(" ".join(words[1:]), cov, approx, depth)
        return
    for i, word in enumerate(words):
        name = _basename(word)
        for pattern, options, subcommands, language in _INLINE_RUNNERS:
            if not pattern.match(name):
                continue
            code = _inline_code(words, i, options, subcommands)
            if code is None:
                continue
            cov.nested.append(language)
            if language == "shell:real":
                _nested_shell(code, cov, False, depth)
            elif language == "shell:approx":
                _nested_shell(code, cov, True, depth)
            elif language == "python":
                if not python_is_side_effect_free(code):
                    cov.fail("inline Python with effects beyond computing and printing values")
            else:
                cov.fail("inline " + language.split(":", 1)[1] + " code Kavach cannot parse")
            return


def _nested_shell(code: str, cov: Coverage, approx: bool, depth: int) -> None:
    inner = analyze(code, approximation=approx, _depth=depth + 1)
    if inner is None:
        cov.fail("nested shell code does not parse")
        return
    cov.nested.extend(inner.nested)
    for reason in inner.reasons:
        cov.fail("nested: " + reason)


# Builtins whose only effect is computing a value (print also writes to stdout).
# Anything that can reach files, the network, the process, the import system
# or arbitrary code (open, exec, eval, compile, __import__, getattr, globals,
# input, attribute access, imports) is excluded by construction.
_PURE_BUILTINS = frozenset({
    "print", "len", "str", "int", "float", "bool", "complex", "repr", "ascii", "format",
    "sum", "min", "max", "sorted", "reversed", "range", "enumerate", "zip", "abs", "round",
    "divmod", "pow", "list", "dict", "set", "frozenset", "tuple", "any", "all",
    "chr", "ord", "hex", "oct", "bin", "isinstance", "hash",
})
_PURE_NODES = (
    ast.Module, ast.Expr, ast.Assign, ast.AugAssign, ast.If, ast.For, ast.Pass, ast.Break, ast.Continue,
    ast.Constant, ast.JoinedStr, ast.FormattedValue, ast.Name, ast.Load, ast.Store,
    ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Subscript, ast.Slice, ast.Starred,
    ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare, ast.IfExp,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.comprehension,
    ast.Call, ast.keyword, ast.operator, ast.unaryop, ast.boolop, ast.cmpop, ast.expr_context,
)


def python_is_side_effect_free(code: str) -> bool:
    """True when inline Python only computes values and prints them.

    Every node must be a plain expression/assignment/loop construct, every
    call must be to a name in _PURE_BUILTINS, and no name may be a dunder or
    shadow those builtins. No imports, no attribute access."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return False
    if not tree.body:
        return False
    assigned = {t.id for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.For, ast.AugAssign))
                for t in ast.walk(n.targets[0] if isinstance(n, ast.Assign) else n.target)
                if isinstance(t, ast.Name)}
    if assigned & _PURE_BUILTINS:
        return False
    for n in ast.walk(tree):
        if not isinstance(n, _PURE_NODES):
            return False
        if isinstance(n, ast.Name) and n.id.startswith("__"):
            return False
        if isinstance(n, ast.Call) and not (isinstance(n.func, ast.Name) and n.func.id in _PURE_BUILTINS):
            return False
    return True
