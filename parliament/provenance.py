"""
provenance.py — taxonomy-grounded provenance for Kavach verdicts
================================================================

Every minister verdict can be grounded in a structured cyber-taxonomy chain:

    matched corpus pattern  →  technique ID  →  tactic  →  kill-chain stage

This turns an opaque BLOCK/ALLOW into an auditable, standards-referenced
decision and feeds the (future) attack-stage trajectory reasoning. The chain
is written into the hash-chained ledger so the *grounding* of each verdict is
tamper-evident, not just the verdict text.

DESIGN (decided June 2026):
  - Primary: per-corpus-entry tagging. Each corpus pattern already carries a
    `source` field (e.g. "MITRE ATT&CK T1555.003", "MITRE ATLAS AML.T0051").
    The retrieval match brings that source through on MinisterScan.source; we
    parse the technique ID from it and resolve technique→tactic→stage here.
  - Fallback: when a matched pattern has no parseable source (older entries),
    resolve to the minister's DEFAULT technique set so provenance is always
    populated. The chain records provenance_basis="minister-default" so the
    audit trail is honest about which entries are precisely tagged.

TAXONOMY VERSIONING — IMPORTANT:
  ATLAS technique IDs have churned recently. This table was reconciled against
  ATLAS as surfaced June 2026 and ATT&CK Enterprise v19 (Apr 2026). VERIFY IDs
  at atlas.mitre.org / attack.mitre.org before camera-ready; see notes inline.
  Known recent shifts captured here:
    - AML.T0051        LLM Prompt Injection (Initial Access)
        .000 Direct, .001 Indirect (indirect is a SUB-technique, not T0054)
    - AML.T0053        LLM Plugin Compromise   (NOT "Agent Tool Invocation")
    - AML.T0054        LLM Jailbreak           (NOT "indirect injection")
    - AML.T0080        AI Agent Context Poisoning (.000 Memory, .001 Thread)
    - AML.T0086        Exfiltration via AI Agent Tool Invocation
    - AML.T0110        AI Agent Tool Poisoning
  ATLAS adopts ATT&CK tactic names; we map both ATLAS and ATT&CK techniques
  onto a single ordered kill-chain stage enum so the trajectory monitor can
  reason over a uniform stage axis (future work — provenance only ships now).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict

# Taxonomy snapshot identifiers — recorded in every provenance record so the
# ledger states exactly which framework versions a verdict was grounded in.
ATLAS_VERSION = "ATLAS 2026.05 (snapshot 2026-06)"
ATTACK_VERSION = "ATT&CK Enterprise v19 (2026-04)"

# ── Ordered kill-chain stages (uniform axis over ATLAS + ATT&CK) ─────────────
# Ordering is what the future stage-graph trajectory reasoning will walk; a
# later-stage action following an earlier-stage one in the same session is the
# escalation signal. Index = ordinal position in a canonical intrusion.
STAGE_ORDER = [
    "reconnaissance",        # 0
    "initial-access",        # 1
    "execution",             # 2
    "persistence",           # 3
    "privilege-escalation",  # 4
    "defense-evasion",       # 5
    "credential-access",     # 6
    "discovery",             # 7
    "collection",            # 8
    "command-and-control",   # 9
    "exfiltration",          # 10
    "impact",                # 11
]


@dataclass
class Provenance:
    """Taxonomy-grounded chain attached to a verdict."""
    technique_id:   str          # e.g. "AML.T0051" / "T1555.003" / "UNMAPPED"
    technique_name: str
    tactic:         str          # human-readable tactic
    stage:          str          # one of STAGE_ORDER
    stage_index:    int          # ordinal (−1 if unknown)
    framework:      str          # "ATLAS" | "ATT&CK" | "none"
    framework_version: str
    provenance_basis: str        # "pattern-tagged" | "minister-default" | "unmapped"

    def to_dict(self) -> dict:
        return asdict(self)


# ── Technique → (name, tactic, stage, framework) ─────────────────────────────
# Agent-relevant ATLAS techniques + the ATT&CK techniques actually cited by the
# v2 corpus `source` fields. Not exhaustive — extend as the corpus grows.
_TECH: dict[str, tuple[str, str, str, str]] = {
    # ATLAS (AI/agent-native)
    "AML.T0051":     ("LLM Prompt Injection", "Initial Access", "initial-access", "ATLAS"),
    "AML.T0051.000": ("LLM Prompt Injection: Direct", "Initial Access", "initial-access", "ATLAS"),
    "AML.T0051.001": ("LLM Prompt Injection: Indirect", "Initial Access", "initial-access", "ATLAS"),
    "AML.T0053":     ("LLM Plugin Compromise", "Execution", "execution", "ATLAS"),
    "AML.T0054":     ("LLM Jailbreak", "Privilege Escalation", "privilege-escalation", "ATLAS"),
    "AML.T0080":     ("AI Agent Context Poisoning", "Defense Evasion", "defense-evasion", "ATLAS"),
    "AML.T0080.000": ("AI Agent Context Poisoning: Memory", "Defense Evasion", "defense-evasion", "ATLAS"),
    "AML.T0080.001": ("AI Agent Context Poisoning: Thread", "Defense Evasion", "defense-evasion", "ATLAS"),
    "AML.T0085.001": ("AI Agent Tools (Collection)", "Collection", "collection", "ATLAS"),
    "AML.T0086":     ("Exfiltration via AI Agent Tool Invocation", "Exfiltration", "exfiltration", "ATLAS"),
    "AML.T0110":     ("AI Agent Tool Poisoning", "Persistence", "persistence", "ATLAS"),
    "AML.T0024":     ("Exfiltration via ML Inference API", "Exfiltration", "exfiltration", "ATLAS"),
    # ATT&CK Enterprise (cited by the v2 corpus)
    "T1190":     ("Exploit Public-Facing Application", "Initial Access", "initial-access", "ATT&CK"),
    "T1078":     ("Valid Accounts", "Defense Evasion", "defense-evasion", "ATT&CK"),
    "T1552":     ("Unsecured Credentials", "Credential Access", "credential-access", "ATT&CK"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access", "credential-access", "ATT&CK"),
    "T1555":     ("Credentials from Password Stores", "Credential Access", "credential-access", "ATT&CK"),
    "T1555.003": ("Credentials from Web Browsers", "Credential Access", "credential-access", "ATT&CK"),
    "T1539":     ("Steal Web Session Cookie", "Credential Access", "credential-access", "ATT&CK"),
    "T1083":     ("File and Directory Discovery", "Discovery", "discovery", "ATT&CK"),
    "T1005":     ("Data from Local System", "Collection", "collection", "ATT&CK"),
    "T1071":     ("Application Layer Protocol", "Command and Control", "command-and-control", "ATT&CK"),
    "T1567":     ("Exfiltration Over Web Service", "Exfiltration", "exfiltration", "ATT&CK"),
    "T1041":     ("Exfiltration Over C2 Channel", "Exfiltration", "exfiltration", "ATT&CK"),
    "T1059":     ("Command and Scripting Interpreter", "Execution", "execution", "ATT&CK"),
    "T1105":     ("Ingress Tool Transfer", "Command and Control", "command-and-control", "ATT&CK"),
    # --- corpus-cited techniques (added from eval_provenance coverage pass) ---
    "T1003":     ("OS Credential Dumping", "Credential Access", "credential-access", "ATT&CK"),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access", "credential-access", "ATT&CK"),
    "T1018":     ("Remote System Discovery", "Discovery", "discovery", "ATT&CK"),
    "T1027":     ("Obfuscated Files or Information", "Defense Evasion", "defense-evasion", "ATT&CK"),
    "T1027.003": ("Obfuscated Files: Steganography", "Defense Evasion", "defense-evasion", "ATT&CK"),
    "T1029":     ("Scheduled Transfer", "Exfiltration", "exfiltration", "ATT&CK"),
    "T1048.002": ("Exfil Over Alternative Protocol: Asymmetric Encrypted", "Exfiltration", "exfiltration", "ATT&CK"),
    "T1048.003": ("Exfil Over Alternative Protocol: Unencrypted", "Exfiltration", "exfiltration", "ATT&CK"),
    "T1053":     ("Scheduled Task/Job", "Persistence", "persistence", "ATT&CK"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence", "persistence", "ATT&CK"),
    "T1057":     ("Process Discovery", "Discovery", "discovery", "ATT&CK"),
    "T1070":     ("Indicator Removal", "Defense Evasion", "defense-evasion", "ATT&CK"),
    "T1070.004": ("Indicator Removal: File Deletion", "Defense Evasion", "defense-evasion", "ATT&CK"),
    "T1074":     ("Data Staged", "Collection", "collection", "ATT&CK"),
    "T1082":     ("System Information Discovery", "Discovery", "discovery", "ATT&CK"),
    "T1087":     ("Account Discovery", "Discovery", "discovery", "ATT&CK"),
    "T1095":     ("Non-Application Layer Protocol", "Command and Control", "command-and-control", "ATT&CK"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence", "persistence", "ATT&CK"),
    "T1102":     ("Web Service", "Command and Control", "command-and-control", "ATT&CK"),
    "T1102.002": ("Web Service: Bidirectional Communication", "Command and Control", "command-and-control", "ATT&CK"),
    "T1111":     ("Multi-Factor Authentication Interception", "Credential Access", "credential-access", "ATT&CK"),
    "T1136":     ("Create Account", "Persistence", "persistence", "ATT&CK"),
    "T1137":     ("Office Application Startup", "Persistence", "persistence", "ATT&CK"),
    "T1195.001": ("Supply Chain Compromise: Software Dependencies", "Initial Access", "initial-access", "ATT&CK"),
    "T1195.002": ("Supply Chain Compromise: Software Supply Chain", "Initial Access", "initial-access", "ATT&CK"),
    "T1217":     ("Browser Information Discovery", "Discovery", "discovery", "ATT&CK"),
    "T1490":     ("Inhibit System Recovery", "Impact", "impact", "ATT&CK"),
    "T1496":     ("Resource Hijacking", "Impact", "impact", "ATT&CK"),
}

# ── Per-minister default technique (fallback when a match is untagged) ────────
# Coarse but honest; provenance_basis records that it was a default.
_MINISTER_DEFAULT: dict[str, str] = {
    "EXECUTOR":  "T1059",         # command/script execution
    "VAULT":     "T1552",         # unsecured credentials
    "CHANNEL":   "AML.T0086",     # exfiltration via agent tool
    "NAVIGATOR": "AML.T0051.001", # indirect prompt injection / nav manipulation
}

# Matches "T1555.003", "AML.T0051", "AML.T0080.001" anywhere in a source string.
_ID_RE = re.compile(r"\b(AML\.T\d{4}(?:\.\d{3})?|T\d{4}(?:\.\d{3})?)\b")
# Secondary identifiers used in the corpus when no ATT&CK/ATLAS ID is present.
_CWE_RE = re.compile(r"\bCWE-(\d+)\b")
_OWASP_RE = re.compile(r"\bA0(\d)\b")  # OWASP Agentic 2026 A0x

# CWE → (name, tactic, stage). Only the CWEs the corpus actually cites.
_CWE: dict[str, tuple[str, str, str]] = {
    "CWE-94":   ("Code Injection", "Execution", "execution"),
    "CWE-88":   ("Argument Injection", "Execution", "execution"),
    "CWE-611":  ("XML External Entity (XXE)", "Initial Access", "initial-access"),
    "CWE-1336": ("Server-Side Template Injection", "Execution", "execution"),
    "CWE-1333": ("Inefficient Regular Expression (ReDoS)", "Impact", "impact"),
    "CWE-532":  ("Information Exposure Through Logs", "Collection", "collection"),
}
# OWASP Agentic 2026 top-level category → (name, tactic, stage).
_OWASP: dict[str, tuple[str, str, str]] = {
    "A01": ("Agent Authorization/Control Hijacking", "Privilege Escalation", "privilege-escalation"),
    "A02": ("Agent Critical-System Interaction", "Execution", "execution"),
    "A04": ("Agent Resource/Service Exhaustion", "Impact", "impact"),
    "A05": ("Agent Cascading/Orchestration Failure", "Impact", "impact"),
    "A09": ("Agent Untraceability/Repudiation", "Defense Evasion", "defense-evasion"),
}


def _resolve_id(tech_id: str, basis: str) -> Provenance:
    entry = _TECH.get(tech_id)
    if entry is None:
        # Try parent technique if a sub-technique is unmapped (e.g. .002).
        if "." in tech_id:
            entry = _TECH.get(tech_id.split(".")[0])
    if entry is None:
        return Provenance(
            technique_id=tech_id, technique_name="(unmapped technique)",
            tactic="unknown", stage="unknown", stage_index=-1,
            framework="none", framework_version="-", provenance_basis="unmapped")
    name, tactic, stage, framework = entry
    return Provenance(
        technique_id=tech_id, technique_name=name, tactic=tactic, stage=stage,
        stage_index=STAGE_ORDER.index(stage) if stage in STAGE_ORDER else -1,
        framework=framework,
        framework_version=ATLAS_VERSION if framework == "ATLAS" else ATTACK_VERSION,
        provenance_basis=basis)


def trajectory_provenance() -> Provenance:
    """Provenance for a session-level trajectory-ceiling block. No single
    minister or technique caused it — it is a multi-step stage progression —
    so we deliberately do NOT cite a technique ID (citing one would be false
    provenance). The stage is left unknown; the basis names the cause."""
    return Provenance(
        technique_id="N/A (session trajectory)",
        technique_name="Multi-step trajectory escalation",
        tactic="(session-level)", stage="unknown", stage_index=-1,
        framework="none", framework_version="-",
        provenance_basis="session-trajectory")


def resolve(source: str | None, minister: str) -> Provenance:
    """Resolve a matched pattern's `source` string to a provenance chain.

    `source` is the corpus pattern's source field carried through on the
    MinisterScan (e.g. "MITRE ATT&CK T1555.003"). When it yields no parseable
    technique ID, fall back to the minister's default technique."""
    if source:
        m = _ID_RE.search(source)
        if m:
            return _resolve_id(m.group(1), basis="pattern-tagged")
        # No ATT&CK/ATLAS technique — try CWE, then OWASP-Agentic, before
        # falling back to the minister default. These give real (if coarser)
        # tactic/stage grounding rather than a generic default.
        cm = _CWE_RE.search(source)
        if cm and f"CWE-{cm.group(1)}" in _CWE:
            name, tactic, stage = _CWE[f"CWE-{cm.group(1)}"]
            return Provenance(
                technique_id=f"CWE-{cm.group(1)}", technique_name=name,
                tactic=tactic, stage=stage,
                stage_index=STAGE_ORDER.index(stage) if stage in STAGE_ORDER else -1,
                framework="CWE", framework_version="CWE List 4.x",
                provenance_basis="pattern-tagged-cwe")
        om = _OWASP_RE.search(source)
        if om and f"A0{om.group(1)}" in _OWASP:
            name, tactic, stage = _OWASP[f"A0{om.group(1)}"]
            return Provenance(
                technique_id=f"OWASP-A0{om.group(1)}", technique_name=name,
                tactic=tactic, stage=stage,
                stage_index=STAGE_ORDER.index(stage) if stage in STAGE_ORDER else -1,
                framework="OWASP-Agentic", framework_version="OWASP Agentic 2026",
                provenance_basis="pattern-tagged-owasp")
    default_id = _MINISTER_DEFAULT.get(minister)
    if default_id:
        return _resolve_id(default_id, basis="minister-default")
    return Provenance(
        technique_id="UNMAPPED", technique_name="(no mapping)", tactic="unknown",
        stage="unknown", stage_index=-1, framework="none",
        framework_version="-", provenance_basis="unmapped")
