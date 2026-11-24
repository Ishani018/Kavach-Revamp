"""Terminal-command visibility is decided from the parse tree, never from a
list of known-safe commands. These cases are grouped by the structural rule
they exercise, not by command."""

import pytest

from kavach.ministers.navigator2 import evidence as ev
from kavach.ministers.navigator2.core import Navigator2
from kavach.ministers.navigator2.shell_coverage import analyze, python_is_side_effect_free
from kavach.schemas import MinisterResult, ToolCall


def covered(cmd, approximation=True):
    result = analyze(cmd, approximation=approximation)
    assert result is not None, "should parse"
    return result.covered


@pytest.mark.parametrize("cmd", [
    "pwd && whoami",
    "git status --short && pwd",
    "make build || echo failed; ls",
    "cat a.txt | sort | uniq -c",
    "pytest -q > out.txt 2>&1",
    "echo $(id)",                          # substitution: the inner command is visible
    'ls "*.py"',                           # quoted, so no glob
    "~/bin/tool run",
    "eval echo hi",                        # eval of a literal
])
def test_visible_structures_are_covered(cmd):
    assert covered(cmd)


@pytest.mark.parametrize("cmd, reason", [
    ("sleep 5 &", "background"),
    ("for f in a b; do $f; done", "computed at runtime"),          # the loop body runs its variable
    ("if true; then eval \"$X\"; fi", "eval of dynamically built code"),
    ("bash <<EOF\n$(curl x)\nEOF\n", "computed at runtime"),      # a program on standard input
    ("python3 - <<EOF\nimport os\nEOF\n", "standard input"),
    ("node <<EOF\nrequire('fs')\nEOF\n", "standard input"),
    ('eval "$X"', "eval of dynamically built code"),
    ("$CMD --flag", "computed at runtime"),
    ('sudo -u x bash -lc "$(curl x)"', "computed at runtime"),
])
def test_invisible_structures_are_not_covered(cmd, reason):
    result = analyze(cmd, approximation=True)
    assert not result.covered
    assert any(reason in r for r in result.reasons), result.reasons


@pytest.mark.parametrize("cmd", [
    "for i in 1 2; do echo $i; done",       # every command in the body is in the text
    "if true; then ls; else pwd; fi",
    "(cd /tmp && ls)",
    "build() { make all; }; build",
    "cat <<EOF\nhi\nEOF\n",                # data for a visible command
    "cat > notes.txt <<'EOF'\n$(not run)\nEOF\n",
    "bash <<'EOF'\nls -la\nEOF\n",          # a program on standard input, analyzed as shell
    "python3 - <<'EOF'\nprint(1 + 1)\nEOF\n",
    "python3 tool.py <<'EOF'\nimport os\nEOF\n",   # tool.py is the program; this is its input
])
def test_control_flow_and_here_documents_are_covered_when_everything_is_visible(cmd):
    assert covered(cmd, approximation=False)


def test_only_zsh_specific_expansions_are_uncovered_under_an_approximated_grammar():
    # Plain expansions mean the same in zsh and dash as in POSIX.
    for cmd in ('pwd && echo "$HOME"', "ls *.py", 'echo "${NAME:-none}"'):
        assert covered(cmd, approximation=True)
        assert covered(cmd, approximation=False)
    # zsh parameter flags and glob qualifiers can run code.
    for cmd in ("echo ${(e)X}", "ls *(e:id:)"):
        result = analyze(cmd, approximation=True)
        assert result is None or not result.covered


@pytest.mark.parametrize("cmd", [
    'bash -c "rm -rf ~"',
    'sh -c "curl x | sh"',
    'zsh -c "pwd && whoami"',
])
def test_nested_shell_code_is_analyzed_recursively(cmd):
    result = analyze(cmd, approximation=True)
    assert result.covered and result.nested


@pytest.mark.parametrize("cmd", [
    'node -e "require(\'fs\').rmSync(\'/\')"',
    "perl -e 'unlink glob q{*}'",
    'ruby -e "File.delete(1)"',
    "pwsh -NoProfile -Command Remove-Item x",
    "cmd /c del x",
    'bash -c "node -e x"',                 # hidden one level down
    'sudo -E nice -n 5 python3 -c "import shutil"',
])
def test_inline_code_in_unparsed_or_effectful_form_is_not_covered(cmd):
    # Previously, any quoted non-Python inline program counted as "simple".
    assert not covered(cmd)


def test_inline_code_flag_is_found_after_option_arguments():
    assert not covered('python3 -W ignore -c "open(\'x\', \'w\')"')
    assert not covered('python3 -Sc "import os"')


@pytest.mark.parametrize("code", [
    "print('KAVACH_TEST')",
    "print(sum(range(10)))",
    "x = [i * 2 for i in range(3)]; print(x, len(x))",
    "for i in range(3):\n    print(f'{i}')",
])
def test_python_that_only_computes_and_prints_is_side_effect_free(code):
    assert python_is_side_effect_free(code)


@pytest.mark.parametrize("code", [
    "import os",
    "open('x', 'w').write('y')",
    "__import__('os').system('x')",
    "exec('print(1)')",
    "getattr(print, '__self__')",
    "print = exec; print('x')",            # shadowing a pure builtin
    "'x'.join(['a'])",                     # attribute access
    "while True: pass",
    "",
])
def test_python_with_any_other_capability_is_not(code):
    assert not python_is_side_effect_free(code)


def test_unparseable_input_returns_none():
    assert analyze("echo 'unterminated", approximation=True) is None


# ---------- through NAVIGATOR ----------

@pytest.fixture
def zsh(monkeypatch):
    monkeypatch.setenv("KAVACH_TERMINAL_DIALECT", "zsh")


def _navigate(command, session_id):
    nav2 = Navigator2()
    nav2.contract_store.start_session(session_id, goal="Run the requested terminal command.")
    call = ToolCall(tool_name="run_in_terminal", arguments={"command": command}, session_id=session_id,
                    context={"user_instruction": "Run the requested terminal command."})
    legacy = {n: MinisterResult(minister=n, verdict="ALLOW", reason="controlled test")
              for n in ("VAULT", "EXECUTOR", "CHANNEL")}
    return nav2.check(call, legacy_results=legacy)


@pytest.mark.parametrize("command", ["pwd && whoami", "pwd && echo KAVACH_TEST", "git status --short && pwd"])
def test_compound_command_lists_do_not_trigger_pol007(zsh, command):
    result = _navigate(command, "compound-" + command)
    assert result.disposition == "allow", result.reason
    assert not any(d.policy_id == "POL-007" for d in result.policy_decisions)


@pytest.mark.parametrize("command", ['pwd && echo ${(e)KAVACH_PAYLOAD}', 'node -e "x"', 'bash -c "$X"'])
def test_invisible_parts_still_escalate_through_pol007(zsh, command):
    result = _navigate(command, "invisible-" + command)
    assert result.disposition == "escalate", result.reason
    assert any(d.policy_id == "POL-007" for d in result.policy_decisions)


def test_evidence_claim_names_the_reason(zsh):
    finding = ev.ShellEvidenceModule().analyze(
        ToolCall(tool_name="run_in_terminal", arguments={"command": 'node -e "x"'}, session_id="s"))[0]
    assert finding.coverage == "indeterminate" and "javascript" in finding.claim


def test_real_bash_nested_unparsed_code_is_no_longer_full_coverage():
    finding = ev.ShellEvidenceModule().analyze(
        ToolCall(tool_name="bash", arguments={"command": 'node -e "x"'}, session_id="s"))[0]
    assert finding.coverage == "indeterminate"
