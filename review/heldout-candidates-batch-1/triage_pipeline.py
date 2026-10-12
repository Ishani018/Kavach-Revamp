#!/usr/bin/env python3
"""
Automated, evidence-based triage of the 256 candidate examples.

What this is: a deterministic rule-based pipeline that PROPOSES classifications from features of the
command text and the source's own metadata. Every output is an unverified heuristic proposal; none is
ground truth, none replaces the source label, and a human audit sample is part of the design.

What it never does:
  * execute or evaluate any command from the dataset (commands are only matched as text, and parsed
    with bashlex, which builds a syntax tree without running anything);
  * run the Kavach MVP or read any of its verdicts, so the triage cannot be circular with the thing
    being tested;
  * modify review_items.jsonl, the source labels or the commands (they are bound by SHA-256).

Reads : review_items.jsonl, ../../kavach/data/kavach_corpus_v1.json and kavach/ministers/prefilters.py
        (only to learn which ATT&CK techniques each minister documents as its scope).
Writes: candidate_triage.jsonl, candidate_triage_summary.json   (both in this folder)

    python triage_pipeline.py
"""
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

PIPELINE_VERSION = "1.0"
SPOT_CHECK_SEED = 20261014
BASELINE_CAP = 25            # how many generic benign commands to keep as noise controls
NEAR_DUP_JACCARD = 0.9

STATUS = "automated_proposal_not_verified"

# ----------------------------------------------------------------------------------------------
# 1. Indicator catalogue. Each entry is a transparent, text-only signal about WHAT A COMMAND DOES.
#    severity: 3 high / 2 medium / 1 low.  group: the threat family it belongs to.
#    These describe the behaviour of the command; none of them looks at any detector.
# ----------------------------------------------------------------------------------------------
I = re.IGNORECASE
INDICATORS = [
    # credential access  -> VAULT family
    ("cred_dump_tooling", 3, "credential_access", re.compile(r"lsass|sekurlsa|mimikatz|ntds\.dit|secretsdump|comsvcs[^\n]*minidump|reg(\.exe)?\s+save\s+hklm\\(sam|security|system)|/etc/shadow|unshadow|dpapi|lazagne", I), "known credential-dumping target or tool"),
    ("cred_secret_literal", 3, "credential_access", re.compile(r"AKIA[0-9A-Z]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----"), "secret-shaped literal in the command"),
    ("cred_store_paths", 2, "credential_access", re.compile(r"\.ssh[/\\]|id_(rsa|dsa|ecdsa|ed25519)\b|\.aws[/\\]credentials|\.netrc|\.pgpass|\.kube[/\\]config|\.docker[/\\]config|login\.keychain|Login Data|logins\.json|cookies\.sqlite|\.kdbx|\.gnupg|\bwallet\.dat|\.git-credentials", I), "reads or references a credential store path"),
    ("cred_store_commands", 2, "credential_access", re.compile(r"security\s+find-(generic|internet)-password|cmdkey\s+/list|vaultcmd|aws\s+secretsmanager|az\s+keyvault|gcloud\s+secrets|vault\s+(read|kv\s+get)|op\s+(item|read)\b|pass\s+show|kubectl\s+get\s+secret|get-credential|\bpassword\b[^\n]{0,20}(--decrypt|-d)\b", I), "queries a secret manager or credential vault"),
    ("password_in_args", 1, "credential_access", re.compile(r"(--password|--passwd)\s*[=:\s]\s*\S|PASSWORD\s*=\s*\S|\bpasswd\b", I), "password handled on the command line"),
    # code execution / persistence / privilege / destruction / evasion / injection  -> EXECUTOR family
    ("download_and_execute", 3, "code_execution", re.compile(r"(curl|wget)[^|;\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\biex\b|invoke-expression|downloadstring|invoke-webrequest[^|\n]*\|\s*iex|certutil[^\n]*-urlcache|bitsadmin[^\n]*/transfer|mshta\s+https?:|regsvr32[^\n]*scrobj|rundll32[^\n]*javascript", I), "fetches remote content and runs it"),
    ("encoded_execution", 3, "code_execution", re.compile(r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}|base64\s+(-d|--decode)[^|\n]*\|\s*(ba)?sh|frombase64string|python[23]?\s+-c\s+[^\n]*(exec|eval|b64decode)|eval\s+[\"']?\$\(", I), "executes encoded or dynamically built code"),
    ("reverse_shell", 3, "code_execution", re.compile(r"/dev/tcp/|\bnc(at)?\b[^\n]*\s(-\w*e\w*|--exec|--sh-exec)\b|bash\s+-i\s*>&|socat[^\n]*exec|mkfifo[^\n]*\bnc\b|tcpclient", I), "interactive shell sent to a remote host"),
    ("script_or_inline_exec", 2, "code_execution", re.compile(r"\b(bash|sh|zsh)\s+-c\b|powershell(\.exe)?\s+[^\n]*-(command|c)\b|cmd(\.exe)?\s+/c\b|\beval\b|start-job|invoke-command|start-process|iex\b|\bexec\b", I), "runs a string or script as code"),
    ("persistence", 2, "persistence", re.compile(r"\bcrontab\b|/etc/cron|schtasks[^\n]*/create|launchctl\s+(load|bootstrap)|LaunchAgents|CurrentVersion\\Run|systemctl\s+enable|\.bashrc|\.zshrc|\.profile|authorized_keys|new-service|\bsc(\.exe)?\s+create|wmic[^\n]*eventfilter|startup\s+folder|nohup\b", I), "installs something that survives a restart or login"),
    ("privilege_change", 2, "privilege_escalation", re.compile(r"\bsu\s+-|chmod\s+[0-7]?[4-7][0-7]{2}\b|chmod\s+[ug]\+s|setuid|visudo|/etc/sudoers|\brunas\b|SeDebugPrivilege|\bdoas\b", I), "raises privilege or changes privilege-related permissions"),
    ("history_read", 1, "credential_access", re.compile(r"(cat|less|more|head|tail|grep|type)\s+[^\n]*(bash|zsh|\.python|psql|mysql)_history|ConsoleHost_history", I), "reads shell or tool history (may hold secrets)"),
    ("sudo_prefix", 1, "privilege_escalation", re.compile(r"(^|[;&|]\s*)sudo\b", I), "runs with elevated rights (routine for administration)"),
    ("offensive_security_tool", 2, "credential_access", re.compile(r"(^|[;&|]\s*|sudo\s+)(hydra|medusa|ncrack|john|hashcat|nikto|sqlmap|msfconsole|msfvenom|aircrack-ng|responder|bettercap|crackmapexec|enum4linux|gobuster|dirb|wpscan)\b", I), "security-testing tool that can be used for attacks"),
    ("destructive", 3, "destruction", re.compile(r"rm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(/|~|\*)|\bdel\s+/[fqs]|format\s+[a-z]:|dd\s+if=\S+\s+of=/dev/|\bmkfs|(^|[;&|]\s*|sudo\s+)shred\b|vssadmin\s+delete|wbadmin\s+delete|bcdedit[^\n]*recoveryenabled|cipher\s+/w|:\(\)\s*\{", I), "deletes or overwrites data"),
    ("process_termination", 2, "destruction", re.compile(r"stop-process|taskkill\s+/f|(^|[;&|]\s*|sudo\s+)(killall|pkill)\b", I), "terminates processes"),
    ("defense_evasion", 3, "defense_evasion", re.compile(r"set-mppreference|disable[^\n]*defender|netsh\s+advfirewall[^\n]*(off|disable)|ufw\s+disable|iptables\s+-F|setenforce\s+0|auditctl\s+-D|wevtutil\s+cl|clear-eventlog|history\s+-c|unset\s+HISTFILE|(rm|truncate|shred|>>?)\s*\S*[^\n]*(bash|zsh)_history|timestomp|attrib\s+\+h|amsi|net\s+stop\s+\S*(defender|firewall|sense)|\brm\b[^\n]*/var/log|>\s*/var/log", I), "weakens defences or removes evidence"),
    ("process_or_kernel_injection", 3, "injection", re.compile(r"ptrace|process.?hollow|createremotethread|virtualallocex|ld_preload|\binsmod\b|\bmodprobe\b|kextload|dyld_insert|inject", I), "injects into a process or loads kernel code"),
    # movement and exfiltration (dual role)
    ("lateral_tooling", 2, "lateral_movement", re.compile(r"psexec|winrm|enter-pssession|wmic[^\n]*/node|\bssh\s+\S+@|\bscp\s|smbclient|net\s+use\s|xfreerdp|\bnet\s+view\b|invoke-wmimethod", I), "reaches another machine"),
    ("data_egress", 2, "exfiltration", re.compile(r"curl[^|\n]*(\s-T\s|--upload-file|-d\s*@|--data-binary\s*@|-F\s+\S+=@)|\bscp\b[^\n]*:|\bnc\b\s+\S+\s+\d+\s*<|invoke-webrequest[^\n]*-infile|invoke-restmethod[^\n]*-method\s+post|\brclone\s+(copy|sync)|aws\s+s3\s+(cp|sync)|gsutil\s+cp|\bftp\b|\btftp\b|-method\s+post[^\n]*-body|\.upload\(", I), "sends data out"),
    ("data_staging", 1, "exfiltration", re.compile(r"compress-archive|7z(\.exe)?\"?\s+a\b|\btar\s+[a-z]*c[a-z]*f", I), "archives files (often routine)"),
    ("lolbin_proxy_execution", 3, "code_execution", re.compile(r"odbcconf|installutil|msbuild(\.exe)?\s|cmstp|regsvr32|rundll32|mshta|wmic[^\n]*process\s+call\s+create|forfiles|pcalua|syncappvpublishingserver", I), "runs code through a trusted system binary"),
    ("offensive_tool_artifact", 3, "code_execution", re.compile(r"sandcat|s4ndc4t|54ndc47|ragdoll|akagi(64)?\.exe|totallylegit|xmrig|memekatz|invoke-mimikatz|\bmanx\b", I), "name of a known offensive tool or implant"),
    ("remote_fetch", 2, "code_execution", re.compile(r"webclient|downloadfile|downloaddata|start-bitstransfer|invoke-webrequest|invoke-restmethod|\bcurl\b|\bwget\b|file/download", I), "downloads content from a remote host"),
    ("security_setting_change", 3, "defense_evasion", re.compile(r"enablelua|set-executionpolicy|executionpolicy\s+(-value\s+)?bypass|policies\\system|add-mppreference|exclusionpath|set-itemproperty[^\n]*(policies|defender)|reg(\.exe)?\s+(add|delete)\s+hk", I), "changes a security setting or policy"),
    ("service_tampering", 2, "persistence", re.compile(r"stop-service|set-service|new-service|sc(\.exe)?\s+(config|stop|delete)|binpath|get-itemproperty[^\n]*services", I), "stops, replaces or installs a service"),
    ("resource_hijack", 3, "destruction", re.compile(r"xmrig|monero|stratum\+tcp|cryptonight|minerd", I), "cryptomining"),
    ("surveillance_capture", 2, "collection", re.compile(r"sox\s+-d|arecord|screencapture|keylog|get-keystrokes|get-clipboard|new-neteventsession|add-neteventprovider|pktmon|wireshark|\bpcap\b|\btcpdump\b", I), "records audio, screen, keystrokes or network traffic"),
    ("credential_search", 2, "credential_access", re.compile(r"reg(\.exe)?\s+query[^\n]*password|findstr[^\n]*password|(dir|find|ls|get-childitem)[^\n]*\.(pem|key|ppk|p12|pfx|kdbx)\b|\.pgp|\.gpg\b", I), "searches for passwords or key files"),
    ("http_post_upload", 2, "exfiltration", re.compile(r"-x\s+post|-method\s+post|system\.net\.http|httpclient|multipartform|file/upload|dropbox|api\.github\.com/repos|--passphrase|gpg\s+-c", I), "uploads or encrypts data for sending"),
    ("defacement_or_disruption", 2, "destruction", re.compile(r"proof that this machine|wifi\.(sh|ps1)|\bwifi\b[^\n]*\boff\b|netsh\s+interface[^\n]*disable|ifconfig\s+\S+\s+down|ip\s+link\s+set\s+\S+\s+down|shutdown\s+(/s|-h|now)", I), "defaces the system or disrupts connectivity"),
    ("history_clearing", 2, "defense_evasion", re.compile(r"clear-history|clear\b\s*$|history\s+-c", I), "clears command history"),
    ("sandbox_sleep", 1, "defense_evasion", re.compile(r"^\s*(sleep|timeout|start-sleep)\s+\d+", I), "delays execution (sandbox-evasion style)"),
    # discovery / reconnaissance  -> NAVIGATOR-scope families
    ("discovery_tooling", 1, "discovery", re.compile(r"\bnmap\b|masscan|netstat|\bss\s+-|arp\s+-a|ifconfig|ipconfig|nslookup|\bdig\b|traceroute|tcpdump|tshark|\bnet\s+(user|group|localgroup)|whoami|\buname\b|systeminfo|tasklist|ps\s+aux|get-process|get-childitem|cat\s+/etc/passwd|\bfind\s+/|get-wmiobject|get-ciminstance|dscl|launchctl\s+list", I), "enumerates the host, users, processes or network"),
]
SEVERITY_NAME = {3: "high", 2: "medium", 1: "low"}

# commands whose OWN purpose is dual-use regardless of arguments (used for the dual-use risk estimate only)
DUAL_USE_TOOLS = re.compile(r"\b(nmap|masscan|nc|ncat|netcat|socat|tcpdump|tshark|ssh|scp|rsync|sudo|chmod|chown|dd|openssl|gpg|mount|iptables|ufw|nft|docker|kubectl|aws|az|gcloud|terraform|certutil|bitsadmin|powershell|curl|wget|find|xargs|git)\b", I)
# placeholders whose value can decide what a command executes or touches
DECISIVE_PLACEHOLDER = re.compile(r"\{\{[^}]*(command|cmd|script|exec|url|uri|host|server|address|payload|code)[^}]*\}\}", re.I)
HELP_ONLY = re.compile(r"^\S+\s+(-h|--help|--version|-V|help|version)\s*$", I)
URLISH = re.compile(r"https?://|\b[\w.+-]+@[\w-]+\.[\w.-]+\b|\b\d{1,3}(\.\d{1,3}){3}\b|\+?\d[\d -]{9,}\d")
GROUP_TO_MINISTER = {"credential_access": "VAULT", "code_execution": "EXECUTOR", "persistence": "EXECUTOR",
                     "privilege_escalation": "EXECUTOR", "destruction": "EXECUTOR", "defense_evasion": "EXECUTOR",
                     "injection": "EXECUTOR"}
NAVIGATOR_GROUPS = {"discovery", "defense_evasion", "lateral_movement", "exfiltration", "persistence", "collection"}


def norm(s):
    return re.sub(r"\s+", " ", s.lower()).strip()


def tokens(s):
    return frozenset(re.findall(r"[a-z0-9_./\-$]{2,}", s.lower()))


def sha256(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------------------------------
# 2. Documented scope of each minister (which ATT&CK parent techniques its own definitions cite).
#    Read from the code/corpus as data. No verdicts are involved.
# ----------------------------------------------------------------------------------------------
def minister_scopes():
    parent = lambda t: t.split(".")[0]
    tid = re.compile(r"T\d{4}(?:\.\d{3})?")
    scopes = {"VAULT": set(), "EXECUTOR": set(), "NAVIGATOR": set()}
    from kavach.ministers import prefilters
    for name, _rx, src in prefilters.VAULT_PATTERNS:
        scopes["VAULT"] |= {parent(t) for t in tid.findall(src)}
    for name, _rx, src in prefilters.EXECUTOR_DENYLIST:
        scopes["EXECUTOR"] |= {parent(t) for t in tid.findall(src)}
    corpus = json.loads((ROOT / "kavach" / "data" / "kavach_corpus_v1.json").read_text())
    for p in corpus["NAVIGATOR"]["patterns"]:
        scopes["NAVIGATOR"] |= {parent(t) for t in tid.findall(p.get("source", ""))}
    return scopes


# ----------------------------------------------------------------------------------------------
# 3. Per-item deterministic checks
# ----------------------------------------------------------------------------------------------
def syntax_check(item):
    """Parse-only checks. Nothing is executed."""
    cmd = json.loads(item["transformed_args_json"])["command"]
    tool = item["transformed_tool"]
    res = {"parse_method": None, "parses": None, "note": ""}
    if tool in ("sh", "bash"):
        try:
            import bashlex
            bashlex.parse(cmd)
            res.update(parse_method="bashlex", parses=True)
        except Exception as e:  # bashlex raises its own errors on unsupported syntax
            res.update(parse_method="bashlex", parses=False, note=type(e).__name__)
    else:
        bal = lambda a, b: cmd.count(a) == cmd.count(b)
        ok = bal("(", ")") and bal("{", "}") and bal("[", "]") and cmd.count('"') % 2 == 0
        res.update(parse_method="bracket_and_quote_balance_only", parses=bool(ok),
                   note="no PowerShell/cmd parser is available; this is only a balance check")
    return res


def completeness(item, flags, sx, cmd):
    reasons = []
    if "option_syntax_not_literal" in flags:
        reasons.append("documentation option notation such as [-a|--all] left in the command")
    if "contains_ellipsis" in flags:
        reasons.append("'...' is documentation shorthand")
    if sx["parses"] is False and sx["parse_method"] == "bashlex":
        reasons.append("does not parse as shell")
    if HELP_ONLY.match(cmd.strip()):
        reasons.append("help/version request only")
    if reasons and ("option_syntax_not_literal" in flags or "contains_ellipsis" in flags or sx["parses"] is False or HELP_ONLY.match(cmd.strip())):
        if HELP_ONLY.match(cmd.strip()):
            return "not_a_security_relevant_command", reasons
        return "template_or_fragment", reasons
    partial = []
    if "unresolved_runtime_variable" in flags:
        partial.append("Caldera #{...} run-time variable left literal")
    if "needs_payload_file" in flags:
        partial.append("depends on a payload file that is not part of the command")
    if "placeholders_replaced" in flags:
        n = len(re.findall(r"\{\{", item["original_command"]))
        partial.append(f"{n} documentation placeholder(s) stand in for real values")
    if partial:
        return "partial", partial
    return "complete", ["no placeholders, variables or notation defects detected"]


def indicators(cmd):
    hits = []
    for iid, sev, group, rx, why in INDICATORS:
        if rx.search(cmd):
            hits.append({"id": iid, "severity": SEVERITY_NAME[sev], "group": group, "explains": why})
    return hits


# ----------------------------------------------------------------------------------------------
# 4. Classification
# ----------------------------------------------------------------------------------------------
def classify(item, hits, comp, flags, scopes):
    is_caldera = item["source_dataset"].startswith("MITRE")
    sev = max([{"high": 3, "medium": 2, "low": 1}[h["severity"]] for h in hits], default=0)
    groups = {h["group"] for h in hits}
    n_strong = sum(1 for h in hits if h["severity"] in ("high", "medium"))
    concerns, label_concern = [], None
    insufficient = False

    if is_caldera:
        if sev == 3 and n_strong >= 2:
            label, conf = "likely_malicious", "high"
        elif sev == 3:
            label, conf = "likely_malicious", "medium"
        elif sev == 2:
            label, conf = "dual_use", "medium"
        else:
            label, conf = "dual_use", "low"
            label_concern = "source calls this an attack-emulation action, but nothing in the command alone looks harmful"
            concerns.append("harm depends on context the command does not show")
    else:
        if sev <= 1:
            label, conf = "likely_benign", "high" if sev == 0 else "medium"
        elif sev == 2:
            label, conf = "dual_use", "medium"
        else:
            label, conf = "dual_use", "low"
            label_concern = "documented as legitimate usage, but the command has a high-risk surface"
        # never promote a documented-legitimate example to 'malicious' automatically

    if comp[0] in ("partial",) and sev >= 2:
        concerns.append("command is incomplete: " + "; ".join(comp[1]))
        # A missing value matters when it could change what the command does. If the command already names a
        # high-severity behaviour (sev 3), a missing payload file or run-time variable lowers confidence only.
        decisive = bool(DECISIVE_PLACEHOLDER.search(item["original_command"])) or (
            sev < 3 and ("needs_payload_file" in flags or (is_caldera and "unresolved_runtime_variable" in flags)))
        if decisive or conf == "low":
            insufficient = True
        elif conf == "high":
            conf = "medium"
    if comp[0] == "template_or_fragment":
        conf = "low"
        insufficient = True
        concerns.append("not a runnable command as written")
    if "shell_unspecified" in flags and sev >= 2:
        concerns.append("shell/platform is an assumption (cross-platform page)")
        if conf == "high":
            conf = "medium"
    if "needs_payload_file" in flags:
        concerns.append("effect depends on a payload file not shown")
        if conf == "high":
            conf = "medium"
    if "unresolved_runtime_variable" in flags:
        concerns.append("run-time variable decides the target")
        if conf == "high":
            conf = "medium"
    if is_caldera and not item["ctx_description"].strip():
        concerns.append("source gives no description")

    # relevance to agent-tool security
    if comp[0] == "not_a_security_relevant_command":
        rel = "none"
    elif comp[0] == "template_or_fragment" and sev == 0:
        rel = "none"
    elif sev == 3:
        rel = "high"
    elif sev == 2 or (sev == 1 and DUAL_USE_TOOLS.search(item["transformed_args_json"])):
        rel = "medium"
    else:
        rel = "low"

    # dual-use risk (how likely a context-free judgement is to be wrong)
    if label == "dual_use" and sev == 3:
        dur = "high"
    elif label == "dual_use" and sev == 2:
        dur = "medium"
    elif label in ("likely_malicious",) and sev == 3 and n_strong < 2:
        dur = "medium"
    elif sev >= 2 and DUAL_USE_TOOLS.search(item["transformed_args_json"]) and not is_caldera:
        dur = "medium"
    else:
        dur = "low"

    strong_groups = {h["group"] for h in hits if h["severity"] in ("high", "medium")}
    return dict(label=label, conf=conf, label_concern=label_concern, insufficient=insufficient,
                concerns=concerns, relevance=rel, dual_use_risk=dur, sev=sev, groups=groups, strong_groups=strong_groups)


def minister_tests(item, cls, comp, hits, scopes):
    """Which ministers could this example test meaningfully? Based only on the command's behaviour and
    the minister's documented scope. CHANNEL is never marked testable from a standalone command."""
    is_caldera = item["source_dataset"].startswith("MITRE")
    technique_parent = (item["ctx_technique_id"] or "").split(".")[0]
    usable = comp[0] in ("complete", "partial")
    out, evidence = {}, defaultdict(list)
    label = cls["label"]
    groups = cls["groups"]
    for m in ("VAULT", "EXECUTOR", "NAVIGATOR"):
        mgroups = {g for g, mm in GROUP_TO_MINISTER.items() if mm == m} if m != "NAVIGATOR" else NAVIGATOR_GROUPS
        by_behaviour = bool(groups & mgroups)
        by_technique = bool(technique_parent) and technique_parent in scopes[m]
        if by_behaviour: evidence[m].append("command behaviour matches the minister's threat family")
        if by_technique: evidence[m].append(f"source technique {technique_parent} is in the minister's documented scope")
        if not usable:
            out[m] = "not_applicable"
        elif label == "likely_malicious" and (by_behaviour or by_technique):
            out[m] = "attack_in_scope"
        elif label == "dual_use" and (by_behaviour or by_technique):
            out[m] = "dual_use_in_scope"
        elif label == "likely_benign" and (cls["strong_groups"] & mgroups):
            out[m] = "hard_negative"
        elif label == "likely_benign" and m == "NAVIGATOR" and not cls["strong_groups"]:
            out[m] = "baseline_negative"
            evidence[m].append("generic benign command: tests unnecessary escalation, not semantic understanding")
        else:
            out[m] = "not_applicable"
    out["CHANNEL"] = "not_testable_standalone"
    ev_channel = ["CHANNEL needs a prior sensitive read followed by a destination call; one standalone command cannot test that"]
    confound = bool(URLISH.search(item["transformed_args_json"]))
    if confound:
        ev_channel.append("contains a URL, address or IP: CHANNEL's generic provenance path may react to it for reasons unrelated to the command's intent (confound)")
    evidence["CHANNEL"] = ev_channel
    return out, dict(evidence), confound


def main():
    items = [json.loads(l) for l in (HERE / "review_items.jsonl").read_text(encoding="utf-8").splitlines()]
    scopes = minister_scopes()

    # duplicate clusters over the transformed command (exact, then near)
    cmds = {i["item_id"]: json.loads(i["transformed_args_json"])["command"] for i in items}
    by_norm = defaultdict(list)
    for i in items:
        by_norm[(i["transformed_tool"], norm(cmds[i["item_id"]]))].append(i["item_id"])
    dup_of = {}
    for ids in by_norm.values():
        rep = min(ids, key=lambda x: next(i["source_item_id"] for i in items if i["item_id"] == x))
        for x in ids:
            if x != rep:
                dup_of[x] = (rep, "exact")
    toks = {i["item_id"]: tokens(cmds[i["item_id"]]) for i in items}
    order = sorted(items, key=lambda i: i["source_item_id"])
    for a_i, a in enumerate(order):
        if a["item_id"] in dup_of:
            continue
        for b in order[a_i + 1:]:
            if b["item_id"] in dup_of or a["transformed_tool"] != b["transformed_tool"]:
                continue
            ta, tb = toks[a["item_id"]], toks[b["item_id"]]
            if len(ta) >= 4 and len(ta | tb) and len(ta & tb) / len(ta | tb) >= NEAR_DUP_JACCARD:
                dup_of[b["item_id"]] = (a["item_id"], "near")

    records = []
    for i in items:
        sid = i["item_id"]
        cmd = cmds[sid]
        flags = set(f for f in i["prep_flags"].split(";") if f)
        sx = syntax_check(i)
        comp = completeness(i, flags, sx, cmd)
        hits = indicators(cmd + "\n" + i["original_command"])
        cls = classify(i, hits, comp, flags, scopes)
        tests, evidence, confound = minister_tests(i, cls, comp, hits, scopes)
        meaningful = [m for m in ("VAULT", "EXECUTOR", "NAVIGATOR") if tests[m] in ("attack_in_scope", "dual_use_in_scope", "hard_negative")]
        baseline = tests["NAVIGATOR"] == "baseline_negative"
        records.append(dict(sid=sid, item=i, flags=flags, sx=sx, comp=comp, hits=hits, cls=cls, tests=tests,
                            evidence=evidence, confound=confound, meaningful=meaningful, baseline=baseline))

    # ---- decision rules, evaluated in this order; the first that applies wins -------------------
    baseline_pool = sorted([r["sid"] for r in records if r["baseline"] and r["sid"] not in dup_of and r["cls"]["conf"] in ("high", "medium")],
                           key=lambda s: sha256(f"{SPOT_CHECK_SEED}:{s}"))
    baseline_keep = set(baseline_pool[:BASELINE_CAP])
    for r in records:
        sid, c = r["sid"], r["cls"]
        if sid in dup_of:
            r["decision"], r["rule"] = "exclude", ("X1", f"duplicate of {dup_of[sid][0]} ({dup_of[sid][1]})")
        elif r["comp"][0] in ("template_or_fragment", "not_a_security_relevant_command"):
            r["decision"], r["rule"] = "exclude", ("X2", "not a runnable, security-relevant command as written: " + "; ".join(r["comp"][1]))
        elif not r["meaningful"] and not r["baseline"]:
            r["decision"], r["rule"] = "exclude", ("X3", "no minister has a meaningful test here and it is not a useful generic control")
        elif r["baseline"] and sid not in baseline_keep and not r["meaningful"]:
            r["decision"], r["rule"] = "exclude", ("X4", f"generic benign control beyond the cap of {BASELINE_CAP}")
        elif c["label_concern"]:
            r["decision"], r["rule"] = "further_review", ("R1", "source label and command evidence disagree")
        elif c["insufficient"] and c["label"] != "dual_use":
            r["decision"], r["rule"] = "further_review", ("R2", "source evidence insufficient for a definite label: " + "; ".join(c["concerns"][:2]))
        elif c["dual_use_risk"] == "high":
            r["decision"], r["rule"] = "further_review", ("R3", "high dual-use risk: context-free judgement likely unreliable")
        elif c["conf"] == "low" and c["relevance"] in ("medium", "high"):
            r["decision"], r["rule"] = "further_review", ("R4", "low confidence on a security-relevant command")
        elif r["meaningful"] and c["label"] == "dual_use":
            r["decision"], r["rule"] = "retain", ("K3", "context-dependent by nature: kept as a dual-use stress item with NO expected verdict")
        elif r["meaningful"]:
            r["decision"], r["rule"] = "retain", ("K1", "consistent evidence, complete enough, definite proposed label, tests at least one minister meaningfully")
        else:
            r["decision"], r["rule"] = "retain", ("K2", "generic benign control kept as a noise baseline")
        r["tier"] = {"K1": "core_definite_label", "K3": "dual_use_stress", "K2": "baseline_control"}.get(r["rule"][0])

    # ---- human spot-check sample (deterministic) ----------------------------------------------
    rng = random.Random(SPOT_CHECK_SEED)
    spot = set()
    for dec, frac in (("retain", 0.25), ("exclude", 0.10)):
        pool = sorted(r["sid"] for r in records if r["decision"] == dec)
        spot |= set(rng.sample(pool, max(1, round(len(pool) * frac))))
    for r in records:
        r["spot"] = r["sid"] in spot

    # ---- write -----------------------------------------------------------------------------------
    out_rows = []
    for r in sorted(records, key=lambda r: r["sid"]):
        i = r["item"]
        out_rows.append({
            "item_id": r["sid"],
            "source": {"dataset": i["source_dataset"], "source_item_id": i["source_item_id"], "pinned_version": i["pinned_version"],
                       "source_label_meaning": i["proposed_label_meaning"],
                       "source_metadata": {k: i[k] for k in ("ctx_tactic", "ctx_technique_id", "ctx_technique_name", "ctx_name") if i[k]},
                       "original_command_sha256": sha256(i["original_command"]),
                       "transformed_call_sha256": sha256(i["transformed_call"])},
            "status": STATUS,
            "deterministic_checks": {
                "prep_flags": sorted(r["flags"]),
                "completeness": r["comp"][0], "completeness_reasons": r["comp"][1],
                "syntax": r["sx"],
                "indicators": r["hits"],
                "url_or_address_present": r["confound"],
                "duplicate_of": ({"item_id": dup_of[r["sid"]][0], "kind": dup_of[r["sid"]][1]} if r["sid"] in dup_of else None),
                "ast_path_available_in_mvp": bool(i["transformed_tool"] in ("sh", "bash") and r["sx"]["parses"]),
            },
            "proposed_classification": {
                "status": STATUS,
                "label": r["cls"]["label"],
                "confidence": r["cls"]["conf"],
                "rationale": _rationale(r),
                "unresolved_concerns": r["cls"]["concerns"],
                "label_concern": r["cls"]["label_concern"],
                "source_evidence_insufficient": r["cls"]["insufficient"],
                "relevance_to_agent_tool_security": r["cls"]["relevance"],
                "dual_use_risk": r["cls"]["dual_use_risk"],
            },
            "mvp_test_value": {"status": STATUS, "minister_tests": r["tests"], "evidence": r["evidence"],
                               "meaningful_for": r["meaningful"], "baseline_control_only": r["baseline"] and not r["meaningful"],
                               "channel_confound": r["confound"]},
            "triage": {"status": STATUS, "decision": r["decision"], "tier": r["tier"], "rule_id": r["rule"][0],
                       "reason": r["rule"][1], "include_in_human_spot_check": r["spot"]},
        })
    with open(HERE / "candidate_triage.jsonl", "w", encoding="utf-8") as fh:
        for row in out_rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    summary = summarize(out_rows, scopes)
    (HERE / "candidate_triage_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("total", "decisions", "tiers")}, indent=1))


def _rationale(r):
    c, hits = r["cls"], r["hits"]
    src = "attack-emulation source" if r["item"]["source_dataset"].startswith("MITRE") else "documented-legitimate source"
    if hits:
        ind = ", ".join(sorted({h["id"] for h in hits}))
        return f"{src}; command text matches {ind} (max severity {SEVERITY_NAME[c['sev']]}); completeness {r['comp'][0]}."
    return f"{src}; no risk indicator matched in the command text; completeness {r['comp'][0]}."


def summarize(rows, scopes):
    cnt = lambda f: dict(sorted(Counter(f(r) for r in rows).items()))
    mt = defaultdict(Counter)
    for r in rows:
        for m, v in r["mvp_test_value"]["minister_tests"].items():
            mt[m][v] += 1
    core = [r for r in rows if r["triage"]["tier"] == "core_definite_label"]
    return {
        "pipeline_version": PIPELINE_VERSION,
        "status": STATUS,
        "total": len(rows),
        "decisions": cnt(lambda r: r["triage"]["decision"]),
        "tiers": cnt(lambda r: str(r["triage"]["tier"])),
        "rules_fired": cnt(lambda r: r["triage"]["rule_id"]),
        "by_source_and_decision": cnt(lambda r: f'{r["source"]["dataset"][:8]} / {r["triage"]["decision"]}'),
        "proposed_label": cnt(lambda r: f'{r["source"]["dataset"][:8]} / {r["proposed_classification"]["label"]}'),
        "confidence": cnt(lambda r: r["proposed_classification"]["confidence"]),
        "completeness": cnt(lambda r: r["deterministic_checks"]["completeness"]),
        "relevance": cnt(lambda r: r["proposed_classification"]["relevance_to_agent_tool_security"]),
        "dual_use_risk": cnt(lambda r: r["proposed_classification"]["dual_use_risk"]),
        "label_concerns": sum(1 for r in rows if r["proposed_classification"]["label_concern"]),
        "source_evidence_insufficient": sum(1 for r in rows if r["proposed_classification"]["source_evidence_insufficient"]),
        "duplicates": cnt(lambda r: (r["deterministic_checks"]["duplicate_of"] or {}).get("kind", "none")),
        "channel_confound": sum(1 for r in rows if r["mvp_test_value"]["channel_confound"]),
        "minister_tests": {m: dict(sorted(v.items())) for m, v in sorted(mt.items())},
        "core_by_source_and_label": cnt_core(core),
        "core_meaningful_for": dict(sorted(Counter(m for r in core for m in r["mvp_test_value"]["meaningful_for"]).items())),
        "core_multi_minister": sum(1 for r in core if len(r["mvp_test_value"]["meaningful_for"]) > 1),
        "spot_check_items": sum(1 for r in rows if r["triage"]["include_in_human_spot_check"]),
        "further_review_items": sum(1 for r in rows if r["triage"]["decision"] == "further_review"),
        "minister_scope_techniques": {m: sorted(v) for m, v in scopes.items()},
        "baseline_cap": BASELINE_CAP, "near_duplicate_jaccard": NEAR_DUP_JACCARD, "spot_check_seed": SPOT_CHECK_SEED,
        "input_sha256": {"review_items.jsonl": hashlib.sha256((HERE / "review_items.jsonl").read_bytes()).hexdigest()},
    }


def cnt_core(core):
    c = Counter(f'{r["source"]["dataset"][:8]} / {r["proposed_classification"]["label"]}' for r in core)
    return dict(sorted(c.items()))


if __name__ == "__main__":
    main()
