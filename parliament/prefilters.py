"""
parliament/prefilters.py
=========================

Stage 1 of the Kavach re-architecture (docs/status/REARCHITECTURE_PLAN.md): additive,
deterministic pre-filters that run on EVERY call alongside the existing
cosine-similarity ministers, without changing router/minister-internals/
speaker/trajectory/provenance/ledger. A rule hit short-circuits to BLOCK;
no hit leaves the existing pipeline entirely unchanged.

Two rule sets, per the locked Stage 1 scope:
    VAULT-style  — credential-path / secret-format regex (gitleaks/
                   truffleHog-style patterns), flags READS of credential
                   material.
    EXECUTOR-style — LOLBIN / dangerous-call deny-list, flags EXECUTION
                   of known-dangerous commands or code constructs.

Confidence convention (locked): a rule hit reports confidence=1.0, no
hit reports confidence=0.0 — keeps the existing threshold/speaker/
trajectory-accumulation math unchanged, since those already expect a
[0,1] cosine-shaped value. retrieval_mode="deterministic" (a new third
value alongside the existing "dense"/"hybrid") so logs are honest about
the mechanism. matched_text/reason wording avoids "at sim X" phrasing
for rule hits (fixed here at the source; speaker.py's reason-string
still says "at sim X" for cosine-based ministers, which remains
accurate for those — only the prefilter's own MinisterScan avoids the
now-inaccurate wording).
"""
from __future__ import annotations

import ast
import json
import logging
import re
from dataclasses import dataclass

from .ministers import MinisterScan
from . import struct_parse
from . import ast_parse

# Dialects where ast_parse's real grammar parser is both correct AND fast
# enough for the live hot path (bashlex, pure-Python, ~0.5ms/call --
# confirmed via direct measurement). PowerShell's real AST (via a
# powershell.exe subprocess) is architecturally correct but costs ~1.4s/call
# -- 18x over the 78ms latency budget, disqualifying for live use, same
# class of rejection as the earlier SPLADE/cross-encoder latency decisions
# (docs/status/REARCHITECTURE_PLAN.md). PowerShell and every other dialect (including
# command_prompt, confirmed via direct test that bashlex raises ParsingError
# on real cmd.exe batch syntax) stay on struct_parse.py's tokenizer here;
# ast_parse.py's PowerShell path remains available as an opt-in offline/
# audit tool, not wired into this live path.
_AST_FAST_DIALECTS = frozenset({"sh", "bash"})

log = logging.getLogger("kavach.prefilters")


# ──────────────────────────────────────────────────────────────────────────────
# Call-text parsing — same wire format ministers.py/server.py already use
# ──────────────────────────────────────────────────────────────────────────────

_CALL_RE = re.compile(r"^tool:(?P<tool>\S+)\s+args:(?P<args>\{.*\})\s*$", re.DOTALL)


@dataclass
class ParsedCall:
    tool: str
    args: dict
    raw_text: str


def parse_call(text: str) -> ParsedCall | None:
    """Parse the 'tool:{name} args:{json}' wire format used throughout
    Kavach (confirmed against benchmarks/kavach_agentdojo_defense.py's
    _format_tool_call and parliament/ministers.py's _tokenize). Returns
    None if the text doesn't match (e.g. free-text queries with no tool
    call) — pre-filters simply don't apply to those, same as the
    ministers' existing behavior on non-tool-call text.

    Malformed args JSON is treated the same way (returns None) rather
    than silently degrading to an empty {} — an empty args dict looks
    identical to a real call with no arguments, so a malformed call would
    otherwise silently pass through every prefilter check as if it had no
    args to scan at all. Logged so a malformed call is visible, not just
    dropped."""
    m = _CALL_RE.match(text.strip())
    if not m:
        return None
    tool = m.group("tool")
    try:
        args = json.loads(m.group("args"))
    except json.JSONDecodeError as e:
        log.warning("parse_call: malformed args JSON for tool %r: %s", tool, e)
        return None
    return ParsedCall(tool=tool, args=args, raw_text=text)


def _flatten_arg_values(args: dict) -> list[str]:
    """String-render every leaf value in the args dict (recursing into
    nested dicts/lists) so regex rules can scan file paths, commands, or
    secret-shaped strings wherever they appear in the call, not just at
    the top level."""
    out: list[str] = []

    def _walk(v):
        if isinstance(v, dict):
            for vv in v.values():
                _walk(vv)
        elif isinstance(v, (list, tuple)):
            for vv in v:
                _walk(vv)
        elif v is not None:
            out.append(str(v))

    _walk(args)
    return out


# ──────────────────────────────────────────────────────────────────────────────
# VAULT-style: credential-path / secret-format regex
# ──────────────────────────────────────────────────────────────────────────────
# Patterns modeled on gitleaks/truffleHog's maintained secret-format and
# credential-path rule sets (borrowed pattern shapes, not novel — per
# docs/status/REARCHITECTURE_PLAN.md §2.1). Each entry: (name, compiled regex,
# ATT&CK/CWE source tag for provenance.py).

VAULT_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("dotenv-file",
     re.compile(r"(^|[/\\])\.env(\.[a-zA-Z0-9_]+)?$"),
     "MITRE ATT&CK T1552.001"),
    ("aws-credentials-file",
     re.compile(r"\.aws[/\\]credentials"),
     "MITRE ATT&CK T1552.001"),
    ("ssh-private-key-path",
     re.compile(r"(^|[/\\])(\.ssh[/\\])?id_(rsa|dsa|ecdsa|ed25519)(\.[a-zA-Z0-9]+)?$"),
     "MITRE ATT&CK T1552.004"),
    ("ssh-dir",
     re.compile(r"(^|[/\\])\.ssh[/\\]"),
     "MITRE ATT&CK T1552.004"),
    ("pem-key-file",
     # Boundary-aware, not end-of-string-anchored (was `r"\.pem$"`, found
     # to miss .pem paths embedded in a longer string -- e.g. a narrative
     # sentence like "tar czf ... /workspace/privatekeyfile.pem && curl
     # ..." never matched, since the value doesn't END in .pem, only
     # contains it -- confirmed to affect check_vault()'s real production
     # matching, not just a test artifact). Mirrors ssh-private-key-path's
     # boundary-check style: `.pem` must be followed by end-of-string or a
     # non-word-non-dot character (so a real extension boundary), NOT
     # another dot (rules out `.pem.example`/`.pem.sample`-style false
     # matches on a `.pem`-containing-but-not-`.pem`-extension filename)
     # and NOT a word character (rules out `.pem_backup`).
     re.compile(r"\.pem(?=$|[^\w.])"),
     "MITRE ATT&CK T1552.004"),
    ("aws-access-key-id",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "MITRE ATT&CK T1552.001"),
    # NOTE: an earlier "aws-secret-key-shape" rule (generic 40-char
    # mixed-case/digit blob, no anchor) was deliberately dropped before
    # commit. Adversarial testing showed it both false-positives on
    # ordinary 40-char tokens (session IDs, hashes, JWT-fragment-shaped
    # strings) whenever they happen to land a regex \b boundary at
    # exactly position 40, AND misses real AWS secret keys that are off
    # by even one character or lack a clean boundary at that offset --
    # a rule that is simultaneously too loose and too brittle, built on
    # a coincidence of length rather than a real signal. gitleaks' own
    # real AWS-secret rule pairs the shape with nearby context (a
    # preceding aws_secret_access_key key name or an adjacent AKIA...
    # access-key-id), not shape alone -- the AKIA rule above already
    # covers the more reliable, structurally-anchored half of a real
    # AWS credential leak. Left as a documented gap, not silently
    # dropped, for whoever revisits VAULT's rule set in Stage 2.
    ("gcp-service-account-json-shape",
     re.compile(r'"type"\s*:\s*"service_account"'),
     "MITRE ATT&CK T1552.001"),
    ("private-key-block",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "MITRE ATT&CK T1552.004"),
    ("generic-secret-keyword-path",
     re.compile(r"(^|[/\\])(secrets?|credentials?)\.(json|ya?ml|txt)$", re.IGNORECASE),
     "MITRE ATT&CK T1552.001"),
    # ---- corpus-driven expansion (Track 2, overnight session) ----
    ("env-secret-harvest",
     # corpus provenance: VAULT-002 (env_secret_harvest)
     re.compile(r"os\.environ\.copy\(\)|dict\(os\.environ\)|/proc/self/environ"),
     "MITRE ATT&CK T1552.001"),
    ("dotenv-read-call",
     # corpus provenance: VAULT-003 (dotenv_file_read)
     re.compile(r"dotenv\.values\(|load_dotenv\("),
     "MITRE ATT&CK T1552.001"),
    ("git-credential-store-path",
     # corpus provenance: VAULT-005 (git_credential_store)
     re.compile(r"\.git-credentials|\.netrc\b"),
     "MITRE ATT&CK T1552.001"),
    ("k8s-serviceaccount-token",
     # corpus provenance: VAULT-006/VAULT-056 (kubernetes_service_account)
     re.compile(r"/var/run/secrets/kubernetes\.io/serviceaccount|/run/secrets/kubernetes\.io/serviceaccount"),
     "MITRE ATT&CK T1552.007"),
    ("docker-registry-config",
     # corpus provenance: VAULT-007/VAULT-066 (docker_registry_config)
     re.compile(r"\.docker[/\\]config\.json"),
     "MITRE ATT&CK T1552.001"),
    ("terraform-state-secrets",
     # corpus provenance: VAULT-008 (terraform_state_secrets)
     re.compile(r"terraform\.tfstate|\.tfstate\b|\.terraform[/\\]backend"),
     "MITRE ATT&CK T1552.001"),
    ("cloud-metadata-imds",
     # corpus provenance: VAULT-009/VAULT-010/VAULT-011/VAULT-055 (cloud_metadata_imds)
     re.compile(r"169\.254\.169\.254|metadata\.google\.internal"),
     "MITRE ATT&CK T1552.005"),
    ("gpg-private-key-material",
     # corpus provenance: VAULT-012/VAULT-077 (gpg_private_key_export)
     re.compile(r"--export-secret-keys|\.gnupg[/\\](private-keys-v1\.d|secring\.gpg)"),
     "MITRE ATT&CK T1552.004"),
    ("password-manager-db",
     # corpus provenance: VAULT-013/VAULT-058 (password_manager_db)
     re.compile(r"\.kdbx\b|\bpass show\b|\bgopass show\b|\bbw get item\b|\bop item get\b|\blpass show\b"),
     "MITRE ATT&CK T1555.005"),
    ("npm-token-rc",
     # corpus provenance: VAULT-014/VAULT-079 (npm_token_from_rc)
     re.compile(r"\.npmrc\b|_authToken\s*="),
     "MITRE ATT&CK T1552.001"),
    ("pypirc-token",
     # corpus provenance: VAULT-015/VAULT-079 (pypi_token_from_pypirc)
     re.compile(r"\.pypirc\b"),
     "MITRE ATT&CK T1552.001"),
    ("browser-localstorage-leveldb",
     # corpus provenance: VAULT-016 (jwt_from_browser_storage)
     re.compile(r"leveldb.{0,40}localStorage|webappsstore\.sqlite|localStorage\.getItem"),
     "MITRE ATT&CK T1539"),
    ("cloud-provider-env-key",
     # corpus provenance: VAULT-018/021/022/023/024/025/045/048/049 (named-service env key read)
     re.compile(r"os\.environ(\.get)?\(['\"](STRIPE_SECRET_KEY|STRIPE_API_KEY|DD_API_KEY|SONAR_TOKEN|HEROKU_API_KEY|TWILIO_AUTH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|VAULT_TOKEN|CONSUL_HTTP_TOKEN|GITHUB_TOKEN|GH_TOKEN)['\"]\)|os\.getenv\(['\"](STRIPE_SECRET_KEY|STRIPE_API_KEY|DD_API_KEY|SONAR_TOKEN|HEROKU_API_KEY|TWILIO_AUTH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|VAULT_TOKEN|CONSUL_HTTP_TOKEN|GITHUB_TOKEN|GH_TOKEN)['\"]\)"),
     "MITRE ATT&CK T1552.001"),
    ("database-connection-string",
     # corpus provenance: VAULT-019/VAULT-085 (database_connection_string)
     re.compile(r"\b(postgres|mysql|mongodb(\+srv)?)://[^\s'\"]*:[^\s'\"]*@|DATABASE_URL\b"),
     "MITRE ATT&CK T1552.001"),
    ("gcloud-application-credentials",
     # corpus provenance: VAULT-026/VAULT-065 (gcloud_application_credentials)
     re.compile(r"GOOGLE_APPLICATION_CREDENTIALS|application_default_credentials\.json"),
     "MITRE ATT&CK T1552.001"),
    ("jenkins-secrets-path",
     # corpus provenance: VAULT-027 (jenkins_secret_file)
     re.compile(r"JENKINS_HOME.{0,20}(credentials\.xml|secrets[/\\]master\.key)"),
     "MITRE ATT&CK T1552.001"),
    ("firebase-service-account-json",
     # corpus provenance: VAULT-028 (firebase_service_account)
     re.compile(r"firebase-adminsdk-.*\.json|FIREBASE_CREDENTIALS"),
     "MITRE ATT&CK T1552.001"),
    ("redis-conf-password",
     # corpus provenance: VAULT-029 (redis_password_from_conf)
     re.compile(r"requirepass\b.{0,20}redis\.conf|redis\.conf.{0,20}requirepass"),
     "MITRE ATT&CK T1552.001"),
    ("ansible-vault-password",
     # corpus provenance: VAULT-030 (ansible_vault_password)
     re.compile(r"ANSIBLE_VAULT_PASSWORD_FILE|\.vault_pass\.txt"),
     "MITRE ATT&CK T1552.001"),
    ("maven-settings-credentials",
     # corpus provenance: VAULT-031 (maven_settings_credentials)
     re.compile(r"\.m2[/\\]settings\.xml"),
     "MITRE ATT&CK T1552.001"),
    ("ruby-gem-credentials",
     # corpus provenance: VAULT-032 (ruby_gem_credentials)
     re.compile(r"\.gem[/\\]credentials"),
     "MITRE ATT&CK T1552.001"),
    ("cargo-registry-token",
     # corpus provenance: VAULT-033 (cargo_registry_token)
     re.compile(r"\.cargo[/\\]credentials\.toml|CARGO_REGISTRY_TOKEN"),
     "MITRE ATT&CK T1552.001"),
    ("pulumi-access-token",
     # corpus provenance: VAULT-034 (pulumi_access_token)
     re.compile(r"\.pulumi[/\\]credentials\.json|PULUMI_ACCESS_TOKEN"),
     "MITRE ATT&CK T1552.001"),
    ("pgpass-credentials",
     # corpus provenance: VAULT-036 (pgpass_credentials)
     re.compile(r"\.pgpass\b|PGPASSFILE"),
     "MITRE ATT&CK T1552.001"),
    ("windows-credential-manager-cmd",
     # corpus provenance: VAULT-038/VAULT-082 (windows_credential_manager)
     re.compile(r"\bcmdkey\s+/list\b|\bvaultcmd\s+/listcreds\b|Get-StoredCredential\b"),
     "MITRE ATT&CK T1555.004"),
    ("macos-keychain-dump",
     # corpus provenance: VAULT-039/VAULT-083 (macos_keychain_dump)
     re.compile(r"security\s+dump-keychain|security\s+find-generic-password|security\s+find-internet-password"),
     "MITRE ATT&CK T1555.001"),
    ("okta-token-cache",
     # corpus provenance: VAULT-041 (okta_token_theft)
     re.compile(r"\.okta[/\\]okta\.yaml|\.okta-aws-cli[/\\]cache"),
     "MITRE ATT&CK T1552.001"),
    ("chrome-login-data-sqlite",
     # corpus provenance: VAULT-043/VAULT-051 (chrome_saved_passwords)
     re.compile(r"['\"]Login Data['\"]|logins\.json\b"),
     "MITRE ATT&CK T1555.003"),
    ("terraform-cloud-token",
     # corpus provenance: VAULT-047 (terraform_cloud_token)
     re.compile(r"\.terraform\.d[/\\]credentials\.tfrc\.json|TF_TOKEN_"),
     "MITRE ATT&CK T1552.001"),
    ("artifactory-token",
     # corpus provenance: VAULT-050 (artifactory_token_read)
     re.compile(r"\.jfrog[/\\]jfrog-cli\.conf|JFROG_CLI_ACCESS_TOKEN"),
     "MITRE ATT&CK T1552.001"),
    ("dotenv-outside-workspace",
     # corpus provenance: VAULT-053 (dotenv_in_repo)
     re.compile(r"secrets\.env\b"),
     "MITRE ATT&CK T1552.001"),
    ("gh-glab-cli-creds",
     # corpus provenance: VAULT-054/VAULT-080 (git_credential_files / github_token_disclosure)
     re.compile(r"\.config[/\\]gh[/\\]hosts\.yml|glab-cli[/\\]config\.yml|glab[/\\]config\.yml"),
     "MITRE ATT&CK T1552.001"),
    ("ssh-agent-socket-hijack",
     # corpus provenance: VAULT-057 (ssh_agent_socket)
     re.compile(r"SSH_AUTH_SOCK\b"),
     "MITRE ATT&CK T1563.001"),
    ("shell-history-credential-grep",
     # corpus provenance: VAULT-059 (shell_history_credential_scrape)
     re.compile(r"\.bash_history\b|\.zsh_history\b|\.psql_history\b|\.mysql_history\b"),
     "MITRE ATT&CK T1552.003"),
    ("lsass-memory-dump",
     # corpus provenance: VAULT-060 (process_memory_credential)
     re.compile(r"\blsass\.exe\b|comsvcs\.dll.{0,20}MiniDump|\bprocdump\b", re.IGNORECASE),
     "MITRE ATT&CK T1003.001"),
    ("git-history-secret-scan",
     # corpus provenance: VAULT-062 (secrets_in_git_history)
     re.compile(r"\bgitleaks\b|\btrufflehog\b|\bdetect-secrets\b"),
     "MITRE ATT&CK T1552.001"),
    ("azure-token-cache",
     # corpus provenance: VAULT-064 (azure_credential_cache)
     re.compile(r"\.azure[/\\](msal_token_cache|accessTokens|azureProfile)\.json"),
     "MITRE ATT&CK T1528"),
    ("vscode-jetbrains-secrets-file",
     # corpus provenance: VAULT-067 (vscode_settings_secrets)
     re.compile(r"\.config[/\\]Code[/\\]User[/\\]settings\.json|JetBrains.{0,20}security\.xml"),
     "MITRE ATT&CK T1552.001"),
    ("etc-shadow-sam-ntds",
     # corpus provenance: VAULT-070 (etc_shadow_attempt)
     re.compile(r"/etc/shadow\b|/etc/master\.passwd\b|System32\\\\config\\\\SAM|NTDS\.dit"),
     "MITRE ATT&CK T1003.008"),
    ("kubernetes-secrets-dump-cmd",
     # corpus provenance: VAULT-071 (kubernetes_secrets_dump)
     re.compile(r"kubectl\s+get\s+secrets\b"),
     "MITRE ATT&CK T1552.007"),
    ("secret-manager-bulk-dump-cmd",
     # corpus provenance: VAULT-072 (vault_or_secret_manager_dump)
     re.compile(r"\bvault\s+kv\s+(list|get)\b|secretsmanager\s+(list-secrets|get-secret-value)\b"),
     "MITRE ATT&CK T1552.001"),
    ("dns-exfil-tool-call",
     # corpus provenance: VAULT-073 (credential_exfil_via_dns)
     re.compile(r"\b(dig|nslookup)\b.{0,60}\b(base32|base64)\b", re.IGNORECASE),
     "MITRE ATT&CK T1048.003"),
    ("kerberos-ticket-cache",
     # corpus provenance: VAULT-081 (kerberos_ticket_cache)
     re.compile(r"/tmp/krb5cc_|\bklist\s+-e\b"),
     "MITRE ATT&CK T1558.004"),
    ("openvpn-wireguard-creds",
     # corpus provenance: VAULT-084 (openvpn_credential_files)
     re.compile(r"auth-user-pass\b|anyconnect\.xml\b|PrivateKey\s*=.{0,10}wireguard", re.IGNORECASE),
     "MITRE ATT&CK T1552.001"),
    ("java-keystore-dump",
     # corpus provenance: VAULT-087 (java_keystore)
     re.compile(r"keytool\s+-list\s+-keystore\b"),
     "MITRE ATT&CK T1552.004"),
    ("redis-mongo-unauth-dump",
     # corpus provenance: VAULT-088 (redis_dump_unauthenticated)
     re.compile(r"redis-cli\s+(KEYS\s+\*|SCAN\s+0)\b"),
     "MITRE ATT&CK T1552.001"),
    ("proc-environ-multi-pid",
     # corpus provenance: VAULT-089 (process_environment_via_proc)
     re.compile(r"/proc/\*/environ|/proc/\*/cmdline"),
     "MITRE ATT&CK T1552.003"),
    ("swap-hiberfil-rawmem",
     # corpus provenance: VAULT-090 (memory_swap_credential)
     re.compile(r"hiberfil\.sys\b|/dev/kmem\b|/var/vm/swapfile"),
     "MITRE ATT&CK T1003.001"),
    # ---- Kavach-PB expansion (atomicred/gtfobins gap map, 2026-07-18) ----
    # Each rule below closes a CATEGORY of miss found in the 519-case attack
    # run, matched at the technique level (tool + argument shape), never on a
    # literal test string. Every one was regression-checked against both
    # benign populations (bfcl 793 + benign_v0 55) at 0 new FPs before merge.
    ("credential-file-search",
     # T1552.001/.004 miss category: find/dir/grep sweeping the filesystem
     # for key/credential FILES by extension or well-known name. Requires a
     # search *tool* AND a credential-file target together, so an ordinary
     # `find . -name '*.py'` never matches. gsecdump/mimikatz-style dumpers
     # included (a search for the credential IS the access).
     re.compile(
         r"\b(find|dir|ls|grep|rg|ag|where|Get-ChildItem|gci)\b"
         r"[^\n]{0,120}"
         r"(\.(pem|key|ppk|pfx|p12|keychain|kdbx)\b|"
         r"[/\\]\.(ssh|gnupg|aws|azure|oci)\b|"
         r"\bid_(rsa|dsa|ecdsa|ed25519)\b|"
         r"\.(oci|config)[/\\].{0,20}\btoken\b|"
         r"['\"]?password['\"]?)",
         re.IGNORECASE),
     "MITRE ATT&CK T1552.001"),
    ("browser-credential-store-path",
     # T1555.003/T1539 miss category: reading a browser's saved-password or
     # cookie store by its canonical on-disk name/path. File-name anchored,
     # so it only fires on the actual credential artifact, not on the word
     # "cookie" in prose.
     re.compile(
         r"Cookies\.binarycookies|"
         r"[/\\](Login Data|Cookies|Web Data)\b|"
         r"key[34]\.db\b|logins\.json\b|signons\.sqlite\b|"
         r"[/\\]Library[/\\](Cookies|Application Support[/\\].{0,30}Cookies)|"
         r"cookies\.sqlite\b",
         re.IGNORECASE),
     "MITRE ATT&CK T1555.003"),
    ("cloud-credential-cli-read",
     # T1078.004/T1528/T1552.005 miss category: cloud CLI commands that
     # mint, list, or export credentials/keys. Verb-anchored to the
     # credential-bearing subcommands only (not all of az/gcloud/aws), so
     # a benign `az group list` never matches.
     re.compile(
         r"\baz\s+(account\s+get-access-token|storage\s+account\s+keys\s+list|ad\s+sp\s+credential)\b|"
         r"\bgcloud\s+(auth\s+print-access-token|iam\s+service-accounts\s+keys\s+create)\b|"
         r"\baws\s+(iam\s+create-access-key|sts\s+get-session-token|secretsmanager\s+get-secret-value)\b",
         re.IGNORECASE),
     "MITRE ATT&CK T1552.005"),
    # ---- Kavach-PB expansion, ROUND 2 (2026-07-18) ----
    # Scope-gated: only categories that were BOTH genuinely credential-access
    # AND uncaught by CHANNEL/NAVIGATOR in the server run. Recon (T1018/T1040)
    # and download-and-run cases mis-tagged VAULT were deliberately left to
    # their real owners (see Round 2 report). Regression + generalization
    # checked at 0 new benign FPs before merge.
    ("keychain-keystore-file-read",
     # T1555.001 miss category: reading a macOS keychain DB file directly by
     # path (distinct from the `security` CLI form already covered by
     # macos-keychain-dump). File-name anchored.
     re.compile(
         r"login\.keychain(-db)?\b|/Library/Keychains/|System\.keychain\b",
         re.IGNORECASE),
     "MITRE ATT&CK T1555.001"),
    ("browser-password-dumper-tool",
     # T1555.003 miss category: launching a known browser-credential
     # extraction utility, or reading a Firefox/Chrome profile's saved-login
     # store by path. Tool-name/path anchored -- these binaries and files
     # exist for no benign purpose in an agent context.
     re.compile(
         r"WebBrowserPassView|LaZagne|SharpChrome|"
         r"\bnss3\.dll\b|key4\.db\b|signons\.sqlite\b|"
         r"Firefox[/\\]Profiles[/\\][^\n]{0,40}(logins\.json|key[34]\.db)",
         re.IGNORECASE),
     "MITRE ATT&CK T1555.003"),
    ("json-token-shape-grep",
     # corpus provenance: VAULT-098 (json_token_pattern_grep). Matches a
     # grep/ripgrep/ag invocation whose OWN regex argument literally
     # contains a credential-shaped search pattern (e.g. someone scanning
     # the filesystem for "AKIA[0-9A-Z]{16}"-style strings), not a text
     # containing an actual credential -- that case is already covered by
     # the existing aws-access-key-id rule above. Fixed a double-escaping
     # artifact in the original draft (`ya29\\\\?\.` matched a literal
     # backslash-question-mark, not the intended "ya29\." grep-pattern
     # substring) before merge.
     re.compile(r"AKIA\[0-9A-Z\]|ghp_\[A-Za-z0-9\]|sk-\[A-Za-z0-9\]|ya29\\\.\["),
     "MITRE ATT&CK T1552.001"),
]


# ──────────────────────────────────────────────────────────────────────────────
# Behavioral-primitive taxonomy (Kavach-PB architectural upgrade).
# Each rule name maps to the behavioral PRIMITIVE it implements -- what the
# call DOES, independent of tool name. This is the organizing axis the rule
# set is designed around; the technique tag (T-number/CWE) remains as
# secondary provenance. A rule with no explicit mapping falls back to its
# minister's generic primitive (defensive default, never crashes).
#
# VAULT:   V1 credential-path-read, V2 credential-search,
#          V3 cloud-credential-cli-invocation, V4 browser-credential-store-access,
#          V5 os-credential-dump, V6 secret-format-match.
# EXECUTOR: E1 network-fetch-to-disk, E2 interpreter-eval-spawn,
#          E3 persistence-location-write, E4 privilege-escalation-search-or-write,
#          E5 library-or-module-load, E6 container-escape,
#          E7 deserialization-or-injection.
RULE_PRIMITIVE: dict[str, str] = {
    # ---- VAULT ----
    "dotenv-file": "V1", "aws-credentials-file": "V1", "ssh-private-key-path": "V1",
    "ssh-dir": "V1", "pem-key-file": "V1", "private-key-block": "V6",
    "aws-access-key-id": "V6", "gcp-service-account-json-shape": "V6",
    "generic-secret-keyword-path": "V1", "env-secret-harvest": "V1",
    "dotenv-read-call": "V1", "git-credential-store-path": "V1",
    "k8s-serviceaccount-token": "V3", "docker-registry-config": "V1",
    "terraform-state-secrets": "V1", "cloud-metadata-imds": "V3",
    "gpg-private-key-material": "V1", "password-manager-db": "V1",
    "npm-token-rc": "V1", "pypirc-token": "V1", "browser-localstorage-leveldb": "V4",
    "cloud-provider-env-key": "V1", "database-connection-string": "V6",
    "gcloud-application-credentials": "V1", "jenkins-secrets-path": "V1",
    "firebase-service-account-json": "V1", "redis-conf-password": "V1",
    "ansible-vault-password": "V1", "maven-settings-credentials": "V1",
    "ruby-gem-credentials": "V1", "cargo-registry-token": "V1",
    "pulumi-access-token": "V1", "pgpass-credentials": "V1",
    "windows-credential-manager-cmd": "V5", "macos-keychain-dump": "V5",
    "okta-token-cache": "V1", "chrome-login-data-sqlite": "V4",
    "terraform-cloud-token": "V1", "artifactory-token": "V1",
    "dotenv-outside-workspace": "V1", "gh-glab-cli-creds": "V1",
    "ssh-agent-socket-hijack": "V1", "shell-history-credential-grep": "V2",
    "lsass-memory-dump": "V5", "git-history-secret-scan": "V2",
    "azure-token-cache": "V1", "vscode-jetbrains-secrets-file": "V1",
    "etc-shadow-sam-ntds": "V5", "kubernetes-secrets-dump-cmd": "V3",
    "secret-manager-bulk-dump-cmd": "V3", "dns-exfil-tool-call": "V1",
    "kerberos-ticket-cache": "V5", "openvpn-wireguard-creds": "V1",
    "java-keystore-dump": "V1", "redis-mongo-unauth-dump": "V3",
    "proc-environ-multi-pid": "V1", "swap-hiberfil-rawmem": "V5",
    "credential-file-search": "V2", "browser-credential-store-path": "V4",
    "cloud-credential-cli-read": "V3", "keychain-keystore-file-read": "V5",
    "browser-password-dumper-tool": "V4", "json-token-shape-grep": "V6",
    # ---- EXECUTOR ----
    "curl-pipe-shell": "E1", "wget-pipe-shell": "E1", "certutil-download": "E1",
    "mshta-remote": "E1", "rundll32-script": "E5", "regsvr32-remote": "E5",
    "cmstp-inf": "E1", "powershell-encoded": "E2", "powershell-download-invoke": "E1",
    "dotnet-webclient-download": "E1", "bitsadmin-transfer": "E1",
    "ruby-inline-shell-exec": "E2", "php-inline-system-exec": "E2",
    "python-eval-exec": "E2", "os-system-call": "E2", "subprocess-shell-true": "E2",
    "base64-decode-then-exec": "E7", "gdb-lldb-inject": "E2",
    "nc-reverse-shell": "E2", "pickle-loads-untrusted": "E7",
    "yaml-load-unsafe": "E7", "ld-preload-env-assign": "E5",
    "pythonpath-hijack": "E5", "xargs-shell-exec": "E2",
    "docker-privileged-run": "E6", "cgroup-release-agent-escape": "E6",
    "kernel-module-load-cmd": "E5", "interpreter-repl-sandbox-escape": "E2",
    "cron-drop-in-write": "E3", "systemd-unit-install": "E3",
    "launchd-plist-persistence": "E3", "wmi-event-subscription": "E3",
    "browser-extension-load-flag": "E3", "jndi-lookup-string": "E7",
    "fifo-mkfifo-exec": "E2", "container-runtime-escape-cmd": "E6",
    "git-hook-file-write": "E3", "git-hookspath-config": "E3",
    "ci-workflow-run-block": "E3", "lockfile-integrity-tamper": "E3",
    "dependency-local-path-override": "E3", "direnv-envrc-write": "E3",
    "ssh-authorized-keys-append": "E3", "sudoers-write": "E4",
    "polkit-rule-write": "E4", "path-env-prepend": "E5",
    "windows-run-key-write": "E3", "windows-service-create": "E3",
    "powershell-profile-write": "E3", "chrome-devtools-protocol-connect": "E2",
    "docker-socket-abuse": "E6", "kubectl-exec-cmd": "E2",
    "k8s-privileged-pod-manifest": "E6", "sts-assume-role-cmd": "E3",
    "interpreter-inline-eval-payload": "E2",
    "remote-payload-download-tool": "E1", "shell-rc-persistence-write": "E3",
    "service-binpath-persistence": "E3", "suid-sgid-search": "E4",
    "shadow-passwd-privesc-cmd": "E4", "awk-perl-inline-shell-spawn": "E2",
    "reverse-shell-network-exec": "E2", "lolbin-arbitrary-library-load": "E5",
    "driver-install-lolbin": "E5",
    # structural-parser-backed rules (Part 2)
    "struct-credential-path": "V1", "struct-network-fetch-to-disk": "E1",
}


def primitive_of(rule_name: str, minister: str) -> str:
    """Return the behavioral primitive a rule implements, or a minister-generic
    fallback if unmapped (so a newly-added-but-untagged rule never crashes
    attribution). AST rules pass their underlying rule_name."""
    return RULE_PRIMITIVE.get(rule_name, "V0" if minister == "VAULT" else "E0")


def check_vault(call: ParsedCall) -> MinisterScan | None:
    values = _flatten_arg_values(call.args)
    haystacks = [call.tool] + values
    for text in haystacks:
        for name, pattern, source in VAULT_PATTERNS:
            m = pattern.search(text)
            if m:
                prim = primitive_of(name, "VAULT")
                return MinisterScan(
                    minister="VAULT",
                    verdict="BLOCK",
                    confidence=1.0,
                    matched_id=f"VAULT-PREFILTER:{name}",
                    matched_text=f"[{prim}] rule '{name}' matched {m.group(0)!r} in call to {call.tool}",
                    matched_level="deterministic",
                    source=source,
                    retrieval_mode="deterministic",
                )
    # Structural fallback (V1/V2): a credential-shaped path token anywhere in
    # the call, robust to quoting/reordering the literal regexes above may
    # miss. Runs AFTER the regex rules (they're more specific); structural is
    # the reorder-robust net beneath them. Validated independently in
    # test_struct_parse.py.
    for text in values:
        if call.tool in _AST_FAST_DIALECTS:
            matched, evidence, used_ast = ast_parse.has_credential_path(text, call.tool)
        else:
            matched, evidence = struct_parse.has_credential_path(text)
            used_ast = False
        if matched:
            return MinisterScan(
                minister="VAULT",
                verdict="BLOCK",
                confidence=1.0,
                matched_id="VAULT-PREFILTER:struct-credential-path",
                matched_text=f"[V1] {'AST' if used_ast else 'structural'}: {evidence} in call to {call.tool}",
                matched_level="deterministic",
                source="MITRE ATT&CK T1552.001",
                retrieval_mode="deterministic",
            )
    return None


# ──────────────────────────────────────────────────────────────────────────────
# EXECUTOR-style: LOLBIN / dangerous-call deny-list
# ──────────────────────────────────────────────────────────────────────────────

EXECUTOR_DENYLIST: list[tuple[str, re.Pattern, str]] = [
    ("curl-pipe-shell",
     re.compile(r"\bcurl\b[^|;\n]{0,200}\|\s*(sh|bash|zsh)\b", re.IGNORECASE),
     "CWE-78"),
    ("wget-pipe-shell",
     re.compile(r"\bwget\b[^|;\n]{0,200}\|\s*(sh|bash|zsh)\b", re.IGNORECASE),
     "CWE-78"),
    ("certutil-download",
     re.compile(r"\bcertutil\b.{0,80}-urlcache", re.IGNORECASE),
     "T1105"),
    ("mshta-remote",
     re.compile(r"\bmshta\b\s+https?://", re.IGNORECASE),
     "T1218.005"),
    ("rundll32-script",
     re.compile(r"\brundll32\b.{0,80}(javascript:|GetObject)", re.IGNORECASE),
     "T1218.011"),
    ("regsvr32-remote",
     re.compile(r"\bregsvr32\b.{0,80}(/i:https?://|scrobj\.dll)", re.IGNORECASE),
     "T1218.010"),
    ("cmstp-inf",
     re.compile(r"\bcmstp\b.{0,40}\.inf\b", re.IGNORECASE),
     "T1218.003"),
    ("powershell-encoded",
     re.compile(r"powershell(\.exe)?\b.{0,40}-(enc|e|EncodedCommand)\b", re.IGNORECASE),
     "T1059.001"),
    ("powershell-download-invoke",
     re.compile(r"(Invoke-Expression|IEX)\b.{0,80}(DownloadString|DownloadFile)", re.IGNORECASE),
     "T1059.001"),
    ("dotnet-webclient-download",
     re.compile(r"Net\.WebClient\b.{0,120}\.(DownloadString|DownloadFile)\s*\(", re.IGNORECASE | re.DOTALL),
     "T1105"),
    ("bitsadmin-transfer",
     re.compile(r"\bbitsadmin\b.{0,40}/transfer", re.IGNORECASE),
     "T1197"),
    ("ruby-inline-shell-exec",
     re.compile(r"\bruby\b.{0,20}-e\b.{0,120}(open3|`.*`|system\s*\()", re.IGNORECASE | re.DOTALL),
     "T1059.004"),
    ("php-inline-system-exec",
     re.compile(r"\bphp\b.{0,20}-r\b.{0,120}\b(system|exec|shell_exec|passthru)\s*\(", re.IGNORECASE | re.DOTALL),
     "T1059.004"),
    ("python-eval-exec",
     re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
     "CWE-95"),
    ("os-system-call",
     re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
     "CWE-78"),
    ("subprocess-shell-true",
     re.compile(r"subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True", re.IGNORECASE | re.DOTALL),
     "CWE-78"),
    ("base64-decode-then-exec",
     re.compile(r"(base64\.b64decode|atob)\s*\([^)]*\)[^;\n]{0,60}(exec|eval)\s*\(", re.IGNORECASE),
     "T1027"),
    ("gdb-lldb-inject",
     re.compile(r"\b(gdb\b.{0,40}--pid|lldb\b.{0,40}-p\b)", re.IGNORECASE),
     "T1055"),
    ("nc-reverse-shell",
     re.compile(r"\bnc\b.{0,40}-e\s+/bin/(sh|bash)", re.IGNORECASE),
     "T1059.004"),
    # ---- corpus-driven expansion (Track 2, overnight session) ----
    ("pickle-loads-untrusted",
     # corpus provenance: EXEC-006 (deserialization_exec)
     re.compile(r"pickle\.loads\(|marshal\.loads\("),
     "CWE-502"),
    ("yaml-load-unsafe",
     # corpus provenance: EXEC-006/EXEC-067 (deserialization_exec)
     re.compile(r"yaml\.load\((?!.*SafeLoader)"),
     "CWE-502"),
    ("ld-preload-env-assign",
     # corpus provenance: EXEC-008/EXEC-023/EXEC-063 (dynamic_library_load / ld_preload_injection)
     re.compile(r"LD_PRELOAD\s*=|/etc/ld\.so\.preload\b"),
     "MITRE ATT&CK T1574.006"),
    ("pythonpath-hijack",
     # corpus provenance: EXEC-010 (python_import_hijack)
     re.compile(r"sys\.path\.insert\(0,|PYTHONPATH\s*="),
     "MITRE ATT&CK T1574.007"),
    ("xargs-shell-exec",
     # corpus provenance: EXEC-013 (xargs_injection)
     re.compile(r"\bxargs\b.{0,40}(-I\{\}|sh -c)", re.IGNORECASE),
     "CWE-78"),
    ("docker-privileged-run",
     # corpus provenance: EXEC-015 (docker_privileged_escape)
     re.compile(r"docker\s+run\b.{0,80}(--privileged|-v\s+/:/host|--cap-add=SYS_ADMIN)", re.IGNORECASE),
     "MITRE ATT&CK T1611"),
    ("cgroup-release-agent-escape",
     # corpus provenance: EXEC-022 (cgroup_escape)
     re.compile(r"/sys/fs/cgroup/release_agent|notify_on_release"),
     "MITRE ATT&CK T1611"),
    ("kernel-module-load-cmd",
     # corpus provenance: EXEC-024/EXEC-064 (kernel_module_load)
     re.compile(r"\binsmod\b|\bmodprobe\b.{0,60}(/tmp|/var/tmp)|\bkldload\b", re.IGNORECASE),
     "MITRE ATT&CK T1547.006"),
    ("interpreter-repl-sandbox-escape",
     # corpus provenance: EXEC-026 (interpreter_repl_escape)
     re.compile(r"__class__\.__base__\.__subclasses__\(\)|ctypes\.CDLL\(None\)\.system"),
     "CWE-95"),
    ("cron-drop-in-write",
     # corpus provenance: EXEC-028/EXEC-084 (cron_d_drop)
     re.compile(r"/etc/cron\.d/|/etc/cron\.hourly/|/etc/cron\.daily/|/var/spool/cron/"),
     "MITRE ATT&CK T1053.003"),
    ("systemd-unit-install",
     # corpus provenance: EXEC-029/EXEC-085 (systemd_service_install)
     re.compile(r"/etc/systemd/system/.*\.(service|timer|path)\b"),
     "MITRE ATT&CK T1543.002"),
    ("launchd-plist-persistence",
     # corpus provenance: EXEC-030/EXEC-086 (launchd_persistence)
     re.compile(r"LaunchAgents/.*\.plist|LaunchDaemons/.*\.plist"),
     "MITRE ATT&CK T1543.001"),
    ("wmi-event-subscription",
     # corpus provenance: EXEC-031/EXEC-089 (wmi_subscription)
     re.compile(r"New-WMIEventSubscription|__EventFilter|__EventConsumer|__FilterToConsumerBinding"),
     "MITRE ATT&CK T1546.003"),
    ("browser-extension-load-flag",
     # corpus provenance: EXEC-033/EXEC-077 (browser_extension_install)
     re.compile(r"--load-extension="),
     "MITRE ATT&CK T1176"),
    ("jndi-lookup-string",
     # corpus provenance: EXEC-041 (jndi_injection)
     re.compile(r"\$\{jndi:(ldap|rmi|dns)://"),
     "CWE-917"),
    ("fifo-mkfifo-exec",
     # corpus provenance: EXEC-047 (fifo_exec_trigger)
     re.compile(r"\bmkfifo\b\s+\S+.{0,40}(echo|>)"),
     "CWE-78"),
    ("container-runtime-escape-cmd",
     # corpus provenance: EXEC-051 (container_runtime_escape)
     re.compile(r"\bnsenter\b|\bunshare\b.{0,40}--mount"),
     "MITRE ATT&CK T1611"),
    ("git-hook-file-write",
     # corpus provenance: EXEC-054 (git_hook_install)
     re.compile(r"\.git[/\\]hooks[/\\](pre-commit|post-checkout|post-merge)\b"),
     "MITRE ATT&CK T1546.999"),
    ("git-hookspath-config",
     # corpus provenance: EXEC-055 (git_hook_install)
     re.compile(r"core\.hooksPath\b"),
     "MITRE ATT&CK T1546.999"),
    ("ci-workflow-run-block",
     # corpus provenance: EXEC-058 (ci_pipeline_modification)
     re.compile(r"\.github[/\\]workflows[/\\].*\.ya?ml|\.gitlab-ci\.ya?ml\b|\.circleci[/\\]config\.ya?ml"),
     "MITRE ATT&CK T1195.002"),
    ("lockfile-integrity-tamper",
     # corpus provenance: EXEC-060 (supply_chain_dependency_swap)
     re.compile(r"package-lock\.json\b.{0,20}(integrity|resolved)|yarn\.lock\b|Cargo\.lock\b"),
     "MITRE ATT&CK T1195.001"),
    ("dependency-local-path-override",
     # corpus provenance: EXEC-061 (supply_chain_dependency_swap)
     re.compile(r"\[patch\.crates-io\]|path\s*=\s*['\"]\.\.?/"),
     "MITRE ATT&CK T1195.001"),
    ("direnv-envrc-write",
     # corpus provenance: EXEC-062 (auto_loaded_config)
     re.compile(r"\.envrc\b"),
     "MITRE ATT&CK T1546.004"),
    ("ssh-authorized-keys-append",
     # corpus provenance: EXEC-078 (ssh_authorized_keys)
     re.compile(r"\.ssh[/\\]authorized_keys2?\b"),
     "MITRE ATT&CK T1098.004"),
    ("sudoers-write",
     # corpus provenance: EXEC-080 (sudoers_modification)
     re.compile(r"/etc/sudoers(\.d[/\\][^\s]+)?\b|/etc/doas\.conf\b"),
     "MITRE ATT&CK T1548.003"),
    ("polkit-rule-write",
     # corpus provenance: EXEC-081 (polkit_rule_install)
     re.compile(r"/etc/polkit-1/rules\.d/"),
     "MITRE ATT&CK T1548.003"),
    ("path-env-prepend",
     # corpus provenance: EXEC-083 (path_hijack)
     re.compile(r"export\s+PATH=.{0,10}:\$PATH"),
     "MITRE ATT&CK T1574.007"),
    ("windows-run-key-write",
     # corpus provenance: EXEC-087 (windows_registry_run_key). Bug found
     # and fixed during independent-source generalization testing: the
     # original draft used a double-escaped `\\\\Run` (matching two
     # literal backslashes before "Run"), which never occurs in real
     # `reg add`/PowerShell registry-path syntax (single backslash) --
     # so this rule matched NOTHING in either of its own generalization
     # test variants despite looking superficially plausible. Corrected
     # to a single literal backslash; re-validated against both
     # `reg add "HKCU\...\CurrentVersion\Run"` and PowerShell's
     # `-Path 'HKLM:\...\CurrentVersion\RunOnce'` forms.
     re.compile(r"CurrentVersion\\Run(Once)?(Ex)?\b"),
     "MITRE ATT&CK T1547.001"),
    ("windows-service-create",
     # corpus provenance: EXEC-088 (windows_service_install)
     re.compile(r"\bsc\s+create\b|New-Service\b"),
     "MITRE ATT&CK T1543.003"),
    ("powershell-profile-write",
     # corpus provenance: EXEC-090 (powershell_profile_persistence)
     # IGNORECASE added in Round 2: PowerShell is case-insensitive and real
     # persistence payloads use the lowercase `$profile` automatic variable
     # (`Add-Content $profile ...`), which the original case-sensitive
     # `\$PROFILE` silently missed -- caught by the Round 2 uncaught-by-any
     # census (T1546.013).
     re.compile(r"\$PROFILE\b|Microsoft\.PowerShell_profile\.ps1", re.IGNORECASE),
     "MITRE ATT&CK T1546.013"),
    ("chrome-devtools-protocol-connect",
     # corpus provenance: EXEC-092 (browser_devtools_protocol)
     re.compile(r"localhost:9222\b|Runtime\.evaluate\b"),
     "MITRE ATT&CK T1185"),
    ("docker-socket-abuse",
     # corpus provenance: EXEC-093 (docker_socket_abuse)
     re.compile(r"/var/run/docker\.sock\b|/run/containerd/containerd\.sock\b"),
     "MITRE ATT&CK T1610"),
    ("kubectl-exec-cmd",
     # corpus provenance: EXEC-094 (kubernetes_exec)
     re.compile(r"\bkubectl\s+exec\b|\bkubectl\s+debug\b"),
     "MITRE ATT&CK T1609"),
    ("k8s-privileged-pod-manifest",
     # corpus provenance: EXEC-095 (kubernetes_privileged_pod)
     re.compile(r"privileged:\s*true|hostPID:\s*true|hostNetwork:\s*true"),
     "MITRE ATT&CK T1610"),
    ("sts-assume-role-cmd",
     # corpus provenance: EXEC-097 (cloud_iam_role_assume)
     re.compile(r"sts\s+assume-role(-with-web-identity)?\b"),
     "MITRE ATT&CK T1550.001"),
    # ---- Kavach-PB expansion (atomicred/gtfobins gap map, 2026-07-18) ----
    # Technique-level rules closing EXECUTOR miss categories from the
    # 519-case run. Each requires a dangerous tool AND a dangerous argument
    # shape together; all regression-checked at 0 new benign FPs (bfcl 793 +
    # benign_v0 55) before merge.
    ("remote-payload-download-tool",
     # T1105 miss category: staging a remote payload to local disk via a
     # transfer tool other than curl/wget (already covered). Requires the
     # tool AND a URL/remote-host source, so a benign local `scp file.txt
     # ./` never matches (no scheme, no user@host:remote form).
     # NOTE: a plain `curl -o file http://...` branch was DROPPED after the
     # Step 5 generalization check flagged it false-positiving on an
     # ordinary benign fetch (`curl -o page.html http://example.com`) --
     # unqualified download-to-disk is not inherently malicious, and the
     # genuinely dangerous curl form (pipe-to-shell) is already covered by
     # curl-pipe-shell above. Kept the transfer tools whose ONLY common use
     # in this corpus is remote staging (tftp/sftp/lwp), scp's user@host:remote
     # form, and IWR -OutFile.
     re.compile(
         r"\b(tftp|sftp|lwp-download|lwp-request)\b[^\n]{0,120}https?://|"
         r"\bscp\b\s+[^\n]{0,80}\b[\w.-]+@[\w.-]+:|"
         r"\bInvoke-WebRequest\b[^\n]{0,120}-OutFile",
         re.IGNORECASE),
     "MITRE ATT&CK T1105"),
    ("shell-rc-persistence-write",
     # T1546.004/T1547.001 miss category: appending an exec payload to a
     # shell startup file or writing an autostart entry. Anchored to the
     # canonical rc-file names combined with a write/append redirect or
     # Add-Content, so merely READING ~/.bashrc doesn't match.
     # Round 2: added bare `/etc/profile` (system-wide, not just profile.d/)
     # after the uncaught-by-any census found `echo ... >> /etc/profile`.
     re.compile(
         r"(>>?\s*|Add-Content[^\n]{0,40})"
         r"[^\n]{0,40}(\.bash_profile|\.bashrc|\.zshrc|\.profile|\.bash_login|/etc/profile(\.d/|\b))|"
         r"(\.bash_profile|\.bashrc|\.zshrc|\.profile)[^\n]{0,10}(>>|<<)",
         re.IGNORECASE),
     "MITRE ATT&CK T1546.004"),
    ("service-binpath-persistence",
     # T1543.003 miss category: creating/reconfiguring a Windows service
     # whose binPath points at an interpreter or dropped exe. sc/New-Service
     # already partly covered; this catches the `sc config ... binPath=` and
     # `sc create ... binPath=` execution-payload form specifically.
     re.compile(
         r"\bsc(\.exe)?\s+(create|config)\b[^\n]{0,120}binPath\s*=",
         re.IGNORECASE),
     "MITRE ATT&CK T1543.003"),
    ("suid-sgid-search",
     # T1548.001 miss category: enumerating SUID/SGID binaries as a privesc
     # precursor. `find ... -perm` with a setuid/setgid bit pattern -- a
     # highly specific attack shape, not an ordinary find.
     # Matches setuid (4000), setgid (2000), or combined (6000) mask forms
     # -- the Step 5 check caught an earlier `[64]000` that missed the
     # setgid-only `-2000` variant. Also the symbolic -u+s/-g+s forms.
     re.compile(
         r"\bfind\b[^\n]{0,80}-perm\b[^\n]{0,20}[-/]?[0-7]*[642]000\b|"
         r"\bfind\b[^\n]{0,80}-perm\b[^\n]{0,20}-[ug]\+s\b",
         re.IGNORECASE),
     "MITRE ATT&CK T1548.001"),
    ("shadow-passwd-privesc-cmd",
     # T1548 miss category: direct reads/edits of the shadow password
     # database or forced passwd changes via a privesc primitive. Distinct
     # from VAULT's /etc/shadow path rule -- this catches the getent/passwd
     # command forms.
     re.compile(
         r"\bgetent\s+shadow\b|"
         r"\bpasswd\b\s+(-|--stdin|root\b)|"
         r"echo\b[^\n]{0,30}\|\s*passwd\b",
         re.IGNORECASE),
     "MITRE ATT&CK T1003.008"),
    ("awk-perl-inline-shell-spawn",
     # T1059.004 miss category: using awk/perl/find's exec primitives to
     # spawn a shell -- classic GTFOBins shell-escape. Requires the
     # interpreter AND an explicit shell-spawn construct together.
     re.compile(
         r"\bawk\b[^\n]{0,80}\bBEGIN\b[^\n]{0,60}\bsystem\s*\(|"
         r"\bperl\b[^\n]{0,60}-e\b[^\n]{0,80}(exec|system)\s*\(?['\"]?/bin/(sh|bash)|"
         r"\bfind\b[^\n]{0,80}-exec\b[^\n]{0,40}/bin/(sh|bash)\b",
         re.IGNORECASE | re.DOTALL),
     "MITRE ATT&CK T1059.004"),
    # ---- Kavach-PB expansion, ROUND 2 (2026-07-18) ----
    # Scope-gated to code-execution categories uncaught by any minister.
    # Reverse shells, LOLBin library-loading, and driver install -- each a
    # general tool+argument shape, never a literal custom binary name (those
    # T1055 injector-exe cases were left out as non-generalizable, per the
    # Round 2 report). 0 new benign FPs verified before merge.
    ("reverse-shell-network-exec",
     # T1059/T1059.004 miss category: interactive/reverse shell over a
     # socket. Classic, highly generalizable shapes: a socket construct or
     # netcat/telnet/socket LOLBin bound to a shell, or an interpreter
     # opening a TCPSocket and spawning a shell. Requires the network+shell
     # combination together, so an ordinary `nc -z host 80` port check or a
     # benign `telnet host 25` never matches.
     re.compile(
         r"\bsocket\b\s+-\w*p\w*\s+['\"]?/bin/(sh|bash)|"
         r"\bnc\b[^\n]{0,40}-e\s+/bin/(sh|bash)|"          # reinforces nc-reverse-shell
         r"TCPSocket\.new\([^\n]{0,60}(/bin/(sh|bash)|exec|system|IO\.popen)|"
         r"/inet/tcp/\d+/[^\n]{0,40}(\|&|/bin/(sh|bash))|"
         r"telnet\b[^\n]{0,40}\d+\s*<[^\n]{0,20}(fifo|pipe|socket)",
         re.IGNORECASE | re.DOTALL),
     "MITRE ATT&CK T1059.004"),
    ("lolbin-arbitrary-library-load",
     # T1574 miss category: coercing a benign LOLBin into loading an
     # attacker .so/.dll/.dylib. Requires a known loader tool AND an explicit
     # shared-object argument together -- an ordinary `openssl req` or
     # `mysql -u root` never matches (no lib path).
     # openssl uses single-dash `-engine` (not `--engine`) -- the Step 5
     # generalization check caught the double-dash-only draft missing it.
     re.compile(
         r"\b(tclsh|ssh-keygen|openssl|curl)\b[^\n]{0,60}"
         r"(load\s+\S+\.(so|dll|dylib)\b|-D\s+\S+\.(so|dll|dylib)\b|--?engine[= ]\S*\.(so|dll|dylib)\b)|"
         r"\bmysql\b[^\n]{0,40}--default-auth[= ][^\n]{0,40}(\.\./|\.(so|dll))|"
         r"\bcdll\.LoadLibrary\(|\bctypes\.CDLL\(['\"]?/",
         re.IGNORECASE),
     "MITRE ATT&CK T1574"),
    ("driver-install-lolbin",
     # T1547 miss category: installing a kernel/device driver via pnputil --
     # a persistence/privesc primitive with no benign agent use. Verb-
     # anchored to the install flags, not all of pnputil.
     re.compile(
         r"\bpnputil(\.exe)?\b[^\n]{0,40}(/add-driver|-i\s+-a|/install)",
         re.IGNORECASE),
     "MITRE ATT&CK T1547.006"),
    ("interpreter-inline-eval-payload",
     # corpus provenance: EXEC-052 (interpreter_arg_injection). Narrowed
     # before merge from a bare `python -c`/`node -e` flag match (which
     # would have fired on completely ordinary developer one-liners like
     # `python -c "print(1)"`) to require BOTH the inline-eval flag AND
     # suspicious payload content (os.system/subprocess/exec/eval/base64/
     # a backtick shell-out/an outbound network call) within the same
     # call, mirroring how a real attacker payload actually looks in
     # practice (confirmed against Type B: still catches 11/12 of the
     # `python -c "os.system(...)"`-shaped obfuscated-exfil cases the
     # original broad draft caught, with the same 0 benign FPs across all
     # 144 benign-set calls + 7 LOLBIN-legit cases). Still broader than
     # most other rules in this file by design (inline code execution is
     # inherently more example-shaped than a fixed credential path), so
     # kept as its own distinctly-named rule for easy review/revert.
     re.compile(
         r"\b(python3?|node|perl|ruby)\b\s+(-c|--eval|-e)\s.{0,300}"
         r"(os\.system|subprocess|exec\s*\(|eval\s*\(|base64|`.*`|requests\.(get|post)|"
         r"urllib|socket\.|\bcurl\b|\bwget\b|Popen)",
         re.IGNORECASE | re.DOTALL,
     ),
     "MITRE ATT&CK T1059.006"),
]


# ──────────────────────────────────────────────────────────────────────────────
# Import-alias resolution (AST) — closes the tractable half of
# docs/status/REARCHITECTURE_PLAN.md §2.2's "resolved-call-name tracing" novel-work
# item: `import os as o; o.system(...)` and `from os import system as s;
# s(...)` both defeat EXECUTOR_DENYLIST's pure string matching, since
# neither substring `os.system(` nor a bare `system(` (without knowing it
# resolves to os.system) appears literally in the code. The harder
# variable-bound case (`fn = os.system; fn(...)`) needs real local
# dataflow/def-use tracking, not just import resolution -- deliberately
# OUT OF SCOPE for this pass (docs/status/REARCHITECTURE_PLAN.md's own §2.2 language
# separates "resolved-call-name tracing" from "decode-then-exec dataflow
# tracing" as two distinct novel-work items; only the former is closed
# here). Left as a documented limitation, not attempted.
#
# Only three EXECUTOR_DENYLIST rules are genuinely Python-call-shaped
# (the rest are shell/PowerShell/curl-pipe patterns with no Python AST to
# walk) -- reused here as the ground truth for "dangerous," per instruction
# not to invent a second list:
#   python-eval-exec       -> eval(...) / exec(...)
#   os-system-call         -> os.system(...)
#   subprocess-shell-true  -> subprocess.{run,Popen,call,check_output}(..., shell=True)
_AST_DANGEROUS_CALLS: dict[str, str] = {
    "eval":         "python-eval-exec",
    "exec":         "python-eval-exec",
    "os.system":    "os-system-call",
}
_AST_SUBPROCESS_FUNCS = frozenset({"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"})
_AST_DENYLIST_SOURCE: dict[str, str] = {name: source for name, _pattern, source in EXECUTOR_DENYLIST}


def _build_alias_map(tree: ast.AST) -> dict[str, str]:
    """Walk Import/ImportFrom nodes, return {local_name: resolved_dotted_name}.
    `import os as o` -> {"o": "os"}. `from os import system as s` -> {"s": "os.system"}.
    Unaliased imports are included too (`import os` -> {"os": "os"}, `from os
    import system` -> {"system": "os.system"}) so the resolver below has one
    uniform lookup regardless of whether the code happened to alias anything."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{node.module}.{alias.name}"
    return aliases


def _resolve_call_name(func_node: ast.expr, aliases: dict[str, str]) -> str | None:
    """Resolve a Call node's func expression to a dotted name, through the
    alias map. Handles the two shapes _build_alias_map's entries produce:
    a bare Name (`s(...)` where s is an aliased `from` import) or an
    Attribute on a Name (`o.system(...)` where o is an aliased `import`)."""
    if isinstance(func_node, ast.Name):
        return aliases.get(func_node.id, func_node.id)
    if isinstance(func_node, ast.Attribute) and isinstance(func_node.value, ast.Name):
        base = aliases.get(func_node.value.id, func_node.value.id)
        return f"{base}.{func_node.attr}"
    return None


def _check_executor_ast(text: str) -> MinisterScan | None:
    """AST-based call-name resolution over one candidate string. Returns
    None (not a match, not an error) whenever the text isn't valid Python
    or contains no resolvable dangerous call -- must never crash or flag
    plain non-code text, since EXECUTOR scans arbitrary arg strings that
    are usually NOT code at all."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None

    aliases = _build_alias_map(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        resolved = _resolve_call_name(node.func, aliases)
        if resolved is None:
            continue

        if resolved in _AST_DANGEROUS_CALLS:
            rule_name = _AST_DANGEROUS_CALLS[resolved]
            return MinisterScan(
                minister="EXECUTOR",
                verdict="BLOCK",
                confidence=1.0,
                matched_id=f"EXECUTOR-PREFILTER-AST:{rule_name}",
                matched_text=f"AST-resolved call {resolved!r} (rule {rule_name!r}) via alias resolution",
                matched_level="deterministic",
                source=_AST_DENYLIST_SOURCE.get(rule_name),
                retrieval_mode="deterministic",
            )

        if resolved in _AST_SUBPROCESS_FUNCS:
            has_shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if has_shell_true:
                return MinisterScan(
                    minister="EXECUTOR",
                    verdict="BLOCK",
                    confidence=1.0,
                    matched_id="EXECUTOR-PREFILTER-AST:subprocess-shell-true",
                    matched_text=f"AST-resolved call {resolved!r} with shell=True via alias resolution",
                    matched_level="deterministic",
                    source=_AST_DENYLIST_SOURCE.get("subprocess-shell-true"),
                    retrieval_mode="deterministic",
                )
    return None


def check_executor(call: ParsedCall) -> MinisterScan | None:
    values = _flatten_arg_values(call.args)
    haystacks = [call.tool] + values

    # Cheapest check first: literal regex, exactly as before -- unchanged
    # behavior for every existing case (LOLBIN shell patterns, direct
    # os.system(/eval(/exec( strings, etc).
    for text in haystacks:
        for name, pattern, source in EXECUTOR_DENYLIST:
            m = pattern.search(text)
            if m:
                prim = primitive_of(name, "EXECUTOR")
                return MinisterScan(
                    minister="EXECUTOR",
                    verdict="BLOCK",
                    confidence=1.0,
                    matched_id=f"EXECUTOR-PREFILTER:{name}",
                    matched_text=f"[{prim}] rule '{name}' matched {m.group(0)!r} in call to {call.tool}",
                    matched_level="deterministic",
                    source=source,
                    retrieval_mode="deterministic",
                )

    # AST alias resolution only runs on haystacks the regex pass above
    # didn't already flag -- catches import-aliased/from-import-aliased
    # indirection (import os as o; o.system(...)) that no literal
    # substring match can see.
    for text in haystacks:
        ast_hit = _check_executor_ast(text)
        if ast_hit is not None:
            return ast_hit

    # Structural fallback (E1 network-fetch-to-disk): a URL/remote-host source
    # AND a disk-write destination in the same call, regardless of tool, flag
    # order, or quoting -- robust to the rewording the literal download rules
    # above miss. Runs last (regex rules are more specific). Validated
    # independently in test_struct_parse.py.
    for text in values:
        if call.tool in _AST_FAST_DIALECTS:
            matched, evidence, used_ast = ast_parse.is_network_fetch_to_disk(text, call.tool)
        else:
            matched, evidence = struct_parse.is_network_fetch_to_disk(text)
            used_ast = False
        if matched:
            return MinisterScan(
                minister="EXECUTOR",
                verdict="BLOCK",
                confidence=1.0,
                matched_id="EXECUTOR-PREFILTER:struct-network-fetch-to-disk",
                matched_text=f"[E1] {'AST' if used_ast else 'structural'}: {evidence} in call to {call.tool}",
                matched_level="deterministic",
                source="MITRE ATT&CK T1105",
                retrieval_mode="deterministic",
            )

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Combined entry point
# ──────────────────────────────────────────────────────────────────────────────

def run_prefilters(text: str) -> list[MinisterScan]:
    """Run all Stage 1 pre-filters against the raw call text. Returns a
    list of MinisterScan hits (empty if nothing fired) — additive,
    designed to be unioned with the existing ministers' results before
    combine_verdicts(), never replacing them. Never raises on
    unparseable text (returns [] instead), matching the existing
    ministers' fail-open-on-empty-result behavior."""
    call = parse_call(text)
    if call is None:
        return []
    hits = []
    v = check_vault(call)
    if v:
        hits.append(v)
    e = check_executor(call)
    if e:
        hits.append(e)
    return hits


# ──────────────────────────────────────────────────────────────────────────────
# Pipeline short-circuit eligibility (server.py's response-path optimization)
# ──────────────────────────────────────────────────────────────────────────────
# A denylist, not an allowlist: rules NOT in this set are eligible for
# short-circuit by default, so a new rule automatically earns eligibility
# unless explicitly excluded here — the opposite of requiring every new
# rule to be manually added to a growing allowlist. Per the validated
# design: newest/least-validated rules stay on the FULL synchronous
# pipeline (COMPASS+NAVIGATOR still run before responding) even when they
# fire, until they've earned the same real-world confidence as the
# original, longer-proven rule set. Expand this by REMOVING an entry once
# a rule has enough validation history, not by growing an allowlist.
#
# interpreter-inline-eval-payload: the broadest-match-surface rule in the
# corpus expansion (bare-ish python -c/-e + suspicious-payload heuristic),
# explicitly flagged in its own source comment as needing extra scrutiny
# before being treated as trustworthy as the older, narrower rules.
#
# dotenv-read-call / redis-mongo-unauth-dump / path-env-prepend: the 3
# rules that failed BOTH independent generalization-test variants during
# this session's validation (see rule_generalization_results.json) --
# each still correctly catches its one validated source-syntax case with
# zero benign FPs, but isn't proven to generalize, so it doesn't yet get
# the response-time trust of skipping semantic confirmation.
SHORT_CIRCUIT_INELIGIBLE_RULE_NAMES: frozenset[str] = frozenset({
    "interpreter-inline-eval-payload",
    "dotenv-read-call",
    "redis-mongo-unauth-dump",
    "path-env-prepend",
})


def is_short_circuit_eligible(matched_id: str | None) -> bool:
    """matched_id is formatted as f'{MINISTER}-PREFILTER:{name}' (regex
    hits) or f'{MINISTER}-PREFILTER-AST:{name}' (AST alias-resolution
    hits) -- see check_vault()/check_executor()/_check_executor_ast()
    above. Splits on the LAST ':' to recover the bare rule name
    regardless of which of the two matched_id prefixes was used. CHANNEL
    hits (channel_taint.py's own matched_id convention, not this
    module's) are always eligible -- the denylist only names VAULT/
    EXECUTOR rule identities, since CHANNEL's taint-tracking mechanism
    itself (not a per-rule regex) is the unit of trust there. A None or
    unparseable matched_id is treated as eligible (fail-open toward the
    existing behavior of running the full pipeline is handled by the
    caller checking verdict/confidence first; this function only answers
    the narrower "is this specific rule identity denylisted" question)."""
    if not matched_id or ":" not in matched_id:
        return True
    rule_name = matched_id.rsplit(":", 1)[-1]
    return rule_name not in SHORT_CIRCUIT_INELIGIBLE_RULE_NAMES
