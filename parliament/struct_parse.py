"""parliament/struct_parse.py
============================

Lightweight STRUCTURAL extraction for the two VAULT/EXECUTOR primitives most
sensitive to superficial rewording/quoting/reordering:

  - EXECUTOR E1 network-fetch-to-disk: "is there a URL AND a disk-write
    destination in this call, regardless of tool/flag order/quoting?"
  - VAULT V1/V2 credential-path-read/search: "is there a credential-shaped
    file path token anywhere in this call, however it's quoted or ordered?"

This is deliberately NOT a full shell grammar parser (out of scope). It
tokenizes a command string with light shell-quote awareness, then classifies
each token by ROLE: url / filepath / write-destination-flag / flag / bareword.
The primitive checks then ask structural questions over those roles instead of
matching literal substrings -- so `curl http://x/y -o z.exe`,
`curl -o z.exe http://x/y`, and `curl --output 'z.exe' "http://x/y"` all read
identically.

Design constraint (validated in test_struct_parse below): extraction must not
mis-classify a benign flag/value as a URL or credential path -- false
extractions are reported honestly, not hidden. A conservative bias is
intentional: when unsure, DON'T classify (a missed structural signal falls
through to the regex rules / cosine triage; a false one could cause an FP).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# ── token classification patterns ──────────────────────────────────────────

# URL: a real scheme://host form. Bare "www.x.com" or a domain alone is NOT
# treated as a URL here (too weak a signal, benign strings contain domains).
_URL_RE = re.compile(r"\b(?:https?|ftp|tftp|sftp|scp|smb)://[^\s'\"|;>]+", re.IGNORECASE)

# A user@host:/remote form (scp/rsync remote source/dest) -- a network source
# even without a scheme.
_REMOTE_HOST_RE = re.compile(r"\b[\w.-]+@[\w.-]+:(?:/|\w)")

# File-path-shaped token: an absolute/relative/home path, or a bare filename
# with an extension. Windows and POSIX. Intentionally excludes lone flags.
_PATH_RE = re.compile(
    r"(?:"
    r"[A-Za-z]:\\[^\s'\"|;]+"                 # C:\...
    r"|~?/[^\s'\"|;>]+"                        # /abs or ~/rel
    r"|\.{1,2}/[^\s'\"|;>]+"                   # ./ or ../
    r"|\b[\w.-]+\.[A-Za-z0-9]{1,8}\b"          # bareword.ext
    r")"
)

# Credential-shaped path signal, split into two tiers to avoid over-matching:
#
#  _CRED_PATH_STRONG: well-known credential LOCATIONS/basenames that are
#  credential-bearing regardless of surrounding path context (a `.ssh/` dir,
#  `/etc/shadow`, `.aws/credentials`, a keychain db, browser login stores).
#  These are specific enough to fire on their own.
#
#  _CRED_EXT: a bare credential-file EXTENSION (`.pem`/`.key`/...). This is
#  weaker -- `api.key` in prose is a config-key NAME, not a file -- so the
#  caller (has_credential_path) only counts an extension match when it sits
#  on a genuinely PATH-shaped token (has a separator / home / ./). Found via
#  the Step 7 expanded negative controls: `echo "the api.key setting"` was
#  over-extracted before this split.
_CRED_PATH_STRONG = re.compile(
    r"(^|[/\\])\.(ssh|aws|gnupg|azure|oci|okta|kube|docker)([/\\]|$)"
    r"|\bid_(rsa|dsa|ecdsa|ed25519)\b"
    r"|(^|[/\\])(credentials?|secrets?|\.env|\.netrc|\.pgpass|\.npmrc)\b"
    r"|/etc/(shadow|passwd)\b|login\.keychain|Login Data\b|logins\.json\b"
    r"|key[34]\.db\b|cookies?\.sqlite\b|\.(kdbx|keychain(-db)?|jks|keystore|ovpn|pfx|p12|ppk)\b",
    re.IGNORECASE,
)
_CRED_EXT = re.compile(r"\.(pem|key)\b", re.IGNORECASE)
# A token is "path-shaped" if it carries a real path separator / home / rel
# prefix -- distinguishes `/root/x.key` or `./id.pem` from a bare `api.key`.
_PATH_SHAPED = re.compile(r"[/\\]|~|^\.{1,2}/")

# Glob/wildcard credential target: a bare credential extension on a wildcard
# (e.g. `*.pem`, `*.key`, `id_rsa*`) as used in `find -name`/`ls` searches --
# carries the credential signal without being a resolvable path token.
_CRED_GLOB_RE = re.compile(
    r"\*\.(pem|key|ppk|pfx|p12|kdbx|jks|keystore|ovpn)\b"
    r"|\bid_(rsa|dsa|ecdsa|ed25519)\*",
    re.IGNORECASE,
)

# Write-destination flag: the token that names an output file (so a URL fetch
# lands on disk). Covers curl -o/--output, wget -O, Invoke-WebRequest -OutFile,
# certutil -f (with -urlcache), -OutFile, redirect '>' handled separately.
_WRITE_FLAG_RE = re.compile(
    r"^(?:-o|--output|-O|--output-document|-OutFile|--outfile)$", re.IGNORECASE
)

# Tokens that indicate a disk write independent of a flag: a shell redirect,
# or a download verb whose semantics are "to file".
_REDIRECT_RE = re.compile(r">>?")

# The target of a shell redirect: the path token immediately following a
# `>`/`>>` (optional whitespace). Used by the payload-staging gate to read
# a redirect's destination extension from raw text on the AST path, where
# bashlex exposes the redirect as a RedirectNode rather than a WordNode.
_REDIRECT_TARGET_RE = re.compile(r">>?\s*([^\s'\"|;>]+)")

# .NET/PowerShell method names whose SEMANTICS are "fetch to disk" even with
# no CLI-style write flag -- the method name itself is the write signal
# (DownloadFile writes to the path given as its 2nd arg; DownloadString
# returns to memory and is deliberately NOT included here, since IEX+
# DownloadString is E2 interpreter-eval-spawn territory, not E1). General
# technique-level signal (the .NET WebClient/HttpClient API shape), not a
# literal quote of any one test case's wording.
_DISK_WRITE_METHOD_RE = re.compile(
    r"^(?:DownloadFile|DownloadFileAsync|Save|WriteAllBytes|WriteAllText|CopyTo)$",
    re.IGNORECASE,
)

# Payload-staging discriminator (E1 false-positive fix). A URL + a
# disk-write destination is NOT inherently malicious: an ordinary
# `curl http://host/api/status -o /tmp/status.json` fetches data to a data
# file and is benign. What makes a fetch-to-disk an E1 attack is that it
# STAGES A PAYLOAD -- the fetched bytes are landed as something executable.
# This mirrors EXECUTOR_DENYLIST's remote-payload-download-tool rule, which
# deliberately DROPPED its bare `curl -o` branch for exactly this reason
# (see prefilters.py's comment on that rule): unqualified download-to-disk
# is not an attack, and the genuinely dangerous curl form (pipe-to-shell)
# is covered separately by curl-pipe-shell. The structural layer must apply
# the same exclusion, or it re-introduces the FP the regex layer removed.
#
# Executable/script/library/archive extensions a staged payload lands on --
# the write TARGET carrying one of these is the "this is a payload, not
# data" signal. Data extensions (.json/.html/.csv/.txt/.xml/.log/...) are
# deliberately NOT here: a fetch landing on those is the benign case.
# Anchored to a token END (end-of-string or a non-word/non-dot boundary)
# and matched against the write-DESTINATION token specifically, NOT the raw
# command -- an earlier whole-command scan false-matched `.com` inside the
# source hostname `evil.com`. `.com` (Windows COM executable) is omitted
# entirely: it collides with domain names far too readily to be a reliable
# disk-target signal.
_EXECUTABLE_TARGET_RE = re.compile(
    r"\.(sh|bash|zsh|py|pyc|pl|rb|php|ps1|psm1|bat|cmd|vbs|js|jar|"
    r"exe|dll|so|dylib|bin|elf|msi|scr|deb|rpm|apk|"
    r"tar|tgz|gz|zip|7z|bz2|xz)(?=$|[^\w.])",
    re.IGNORECASE,
)

# Pipe-to-interpreter: a fetch whose output is piped straight into a shell/
# interpreter (the classic `curl ... | sh` shape). Its PRESENCE alongside a
# fetch is itself a payload-execution signal even if no file extension is
# involved. (curl-pipe-shell already BLOCKs the sh/bash/zsh forms at the
# regex layer; this broader interpreter set keeps the structural E1 net
# honest for python/perl/ruby/node pipe targets too, without depending on a
# specific tool name.)
_PIPE_TO_INTERPRETER_RE = re.compile(
    r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|python[23]?|perl|ruby|node|php|pwsh|powershell)\b",
    re.IGNORECASE,
)


# The HTTP-fetch tools that ALSO have a legitimate benign data-fetch use
# (`curl`/`wget` fetching an API/status/page to a data file). ONLY these are
# subject to the payload-staging gate. Staging-only transfer tools
# (tftp/sftp/lwp-download) are NOT here: they have no benign data-fetch use
# in an agent context -- exactly the same tool-partitioning
# remote-payload-download-tool's regex makes (it dropped the `curl -o`
# branch but KEPT tftp/sftp/lwp unconditionally).
_BENIGN_CAPABLE_FETCH_TOOL_RE = re.compile(r"\b(curl|wget)\b", re.IGNORECASE)


def _needs_staging_gate(cmd: str, r: "StructResult") -> bool:
    """Whether the URL-fetch in `cmd` is subject to the payload-staging gate.
    Only curl/wget HTTP(S) fetches are -- those are the ones with a benign
    data-download equivalent (`curl http://host/api/status -o out.json`).
    A tftp/sftp/lwp transfer, a redirect-piped fetch, or any non-curl/wget
    fetch tool is staging-only and stays ungated."""
    if not r.urls:
        return False  # remote-host (scp) branch -- never gated
    return bool(_BENIGN_CAPABLE_FETCH_TOOL_RE.search(cmd))


def _url_fetch_is_payload_staging(cmd: str, r: "StructResult") -> bool:
    """Gate for curl/wget URL fetch-to-disk. Returns True when the fetch
    carries a payload-execution signal:
      - the fetch is piped straight into an interpreter (`curl ... | sh`), OR
      - a write-destination / redirect target token, or the filepath the
        output lands on, carries an executable/script/library/archive
        extension.
    A curl/wget fetch with neither -- a plain data download to a
    .json/.html/.csv file, e.g. `curl http://host/api/status -o
    /tmp/status.json` -- is excluded, mirroring remote-payload-download-tool's
    own dropped `curl -o` branch so the structural layer doesn't re-introduce
    that FP. Only called when _needs_staging_gate() is True."""
    if _PIPE_TO_INTERPRETER_RE.search(cmd):
        return True
    # Candidate disk targets: explicit write-dest tokens, redirect targets
    # (captured as filepaths), and any filepath token the fetch could land
    # on. Check each token for an executable extension -- NOT the raw
    # command (which would false-match a `.gz`/`.zip` etc. inside a URL).
    for dst in list(r.write_destinations) + list(r.filepaths):
        if _EXECUTABLE_TARGET_RE.search(dst):
            return True
    # Redirect target from raw text: bashlex's AST path exposes a redirect
    # only as has_redirect_write (RedirectNode, not a WordNode), so the
    # target token isn't in r.filepaths there. Scan the token immediately
    # after a `>`/`>>` for an executable extension so `curl url > /tmp/x.sh`
    # stages-True identically on both the tokenizer and AST paths.
    for m in _REDIRECT_TARGET_RE.finditer(cmd):
        if _EXECUTABLE_TARGET_RE.search(m.group(1)):
            return True
    return False


@dataclass
class StructResult:
    tokens: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    remote_hosts: list[str] = field(default_factory=list)
    filepaths: list[str] = field(default_factory=list)
    credential_paths: list[str] = field(default_factory=list)
    write_destinations: list[str] = field(default_factory=list)
    has_redirect_write: bool = False


def _is_credential_path(p: str) -> bool:
    """Two-tier credential-path test. A strong location/basename match counts
    on its own; a bare `.pem`/`.key` extension counts ONLY when the token is
    genuinely path-shaped (has a separator/home/rel prefix), so `api.key` in
    prose is not mistaken for a key file."""
    if _CRED_PATH_STRONG.search(p):
        return True
    if _CRED_EXT.search(p) and _PATH_SHAPED.search(p):
        return True
    return False


def _shell_tokenize(cmd: str) -> list[str]:
    """Light shell-quote-aware tokenizer. Splits on unquoted whitespace,
    keeps single/double-quoted spans as one token (quotes stripped). Not a
    full parser -- doesn't handle nested quotes or escaping exhaustively, but
    robust enough for role extraction. Never raises."""
    tokens: list[str] = []
    buf = []
    quote = None
    for ch in cmd:
        if quote:
            if ch == quote:
                quote = None
            else:
                buf.append(ch)
        elif ch in ("'", '"'):
            quote = ch
        elif ch.isspace():
            if buf:
                tokens.append("".join(buf)); buf = []
        else:
            buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return tokens


def extract(cmd: str) -> StructResult:
    """Extract structural roles from a command string. Pure, never raises."""
    r = StructResult()
    if not cmd:
        return r
    r.tokens = _shell_tokenize(cmd)

    # URLs / remote hosts scanned over the RAW string (quoting already handled
    # by the regex's char class; a URL split across tokens is rare and the raw
    # scan is more robust than per-token here).
    r.urls = _URL_RE.findall(cmd)
    r.remote_hosts = [m.group(0) for m in _REMOTE_HOST_RE.finditer(cmd)]

    # Per-token path/flag/redirect classification.
    for i, tok in enumerate(r.tokens):
        if _WRITE_FLAG_RE.match(tok):
            # the write destination is the NEXT token, if present and not a flag
            if i + 1 < len(r.tokens) and not r.tokens[i + 1].startswith("-"):
                r.write_destinations.append(r.tokens[i + 1])
            else:
                r.write_destinations.append(tok)  # flag present even if dest missing
            continue
        if _REDIRECT_RE.fullmatch(tok):
            r.has_redirect_write = True
            continue
        # a token like ">file" or "file" following a bare ">" -- catch inline redirect
        if tok.startswith(">"):
            r.has_redirect_write = True
            rest = tok.lstrip(">")
            if rest:
                r.filepaths.append(rest)
            continue
        # path classification: only tokens that are NOT pure flags
        if tok.startswith("-") and "/" not in tok and "\\" not in tok:
            continue
        for pm in _PATH_RE.finditer(tok):
            p = pm.group(0)
            r.filepaths.append(p)
            if _is_credential_path(p):
                r.credential_paths.append(p)

    # Also scan the whole command for credential paths that the tokenizer may
    # have merged with punctuation (belt-and-suspenders; credential paths are
    # the higher-recall-worth signal).
    for pm in _PATH_RE.finditer(cmd):
        p = pm.group(0)
        if _is_credential_path(p) and p not in r.credential_paths:
            r.credential_paths.append(p)

    # Glob-form credential targets: a search argument like `-name '*.pem'` or
    # `*.key` carries the credential-extension signal without being a full
    # path token (so _PATH_RE misses it). Catch a bare credential extension on
    # a glob/wildcard so `find ... -name '*.pem'` reads as a credential search.
    for gm in _CRED_GLOB_RE.finditer(cmd):
        g = gm.group(0)
        if g not in r.credential_paths:
            r.credential_paths.append(g)

    return r


# ── primitive-level structural predicates ───────────────────────────────────

def is_network_fetch_to_disk(cmd: str) -> tuple[bool, str | None]:
    """E1: a URL/remote-host source AND a disk-write destination in the same
    call. Returns (matched, evidence)."""
    r = extract(cmd)
    has_source = bool(r.urls or r.remote_hosts)
    if not has_source:
        return False, None
    # disk-write destination: an explicit output flag, a redirect, or a
    # local file path token that is NOT itself the URL. For remote-host
    # (scp) the presence of a local path destination is the write.
    has_dest = bool(r.write_destinations) or r.has_redirect_write
    if not has_dest:
        # scp remote:src localdest -- a bare local path alongside a remote host
        if r.remote_hosts and any(
            not _URL_RE.search(p) and "@" not in p for p in r.filepaths
        ):
            has_dest = True
    if has_source and has_dest:
        # Payload-staging gate for URL-sourced fetches ONLY: a bare data
        # fetch-to-disk (no pipe-to-interpreter, no executable-extension
        # target) is benign and must not fire -- see
        # _url_fetch_is_payload_staging() / the E1 FP fix. Remote-host (scp)
        # staging is intentionally NOT gated (higher-signal shape, no
        # benign-data-fetch equivalent, extensionless payloads are real).
        if _needs_staging_gate(cmd, r) and not _url_fetch_is_payload_staging(cmd, r):
            return False, None
        src = (r.urls or r.remote_hosts)[0]
        dst = (r.write_destinations or ["<redirect>"])[0] if (r.write_destinations or r.has_redirect_write) else "<local-path>"
        return True, f"fetch {src!r} -> disk {dst!r}"
    return False, None


def has_credential_path(cmd: str) -> tuple[bool, str | None]:
    """V1/V2: a credential-shaped file path token anywhere in the call."""
    r = extract(cmd)
    if r.credential_paths:
        return True, f"credential path {r.credential_paths[0]!r}"
    return False, None
