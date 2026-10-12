# Definition review, batch 1: nonexistent and revoked ATT&CK IDs

Review and recommendations only. No detection logic, Supabase record, status, rule, migration or commit was changed. All 7 records remain `unreviewed`.

## Summary

| # | Record (`definition_id`) | Minister | Cited ID | ID status in ATT&CK v19.2 | Recommended action |
|---|---|---|---|---|---|
| 1 | `git-hook-file-write` | EXECUTOR | T1546.999 | **Nonexistent** | Correct mapping → T1546 (low confidence; fit unresolved) |
| 2 | `git-hookspath-config` | EXECUTOR | T1546.999 | **Nonexistent** | Correct mapping → T1546 (low confidence; fit unresolved) |
| 3 | `NAV-009` | NAVIGATOR | T1562 | **Revoked**, replaced by T1685 | Revise the pattern (wrong technique *and* behaviour mismatch) |
| 4 | `NAV-022` | NAVIGATOR | T1070.002 | **Revoked**, replaced by T1685.006 | Correct mapping → T1685.006 (+ T1685.005 for the Windows examples) |
| 5 | `NAV-030` | NAVIGATOR | T1562.006 | **Revoked**, replaced by T1685, but never the right technique | Correct mapping → T1685.004 |
| 6 | `NAV-038` | NAVIGATOR | T1562.004 | **Revoked**, replaced by T1686 | Correct mapping → T1686 |
| 7 | `NAV-050` | NAVIGATOR | T1562 | **Revoked**, replaced by T1685 | Correct mapping → T1685 |

Only the first and third rows need real judgement. Rows 4 to 7 are mechanical once the replacement is checked against what the pattern actually describes.

## Evidence base and its limits

- **Source read:** MITRE's published Enterprise ATT&CK STIX bundle, collection **v19.2, modified 2026-08-05**: <https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json>. I read the technique objects, their `revoked` / `x_mitre_deprecated` flags, `revoked-by` relationships, tactics, platforms and descriptions. I did not parse the attack.mitre.org web pages (they respond, but I relied on the bundle). The technique URLs below are the ones the bundle itself lists.
- **Vocabulary used.** *Nonexistent*: no object with that ID in any state (active, revoked or deprecated) in v19.2. *Revoked*: object exists, `revoked: true`, with a `revoked-by` relationship naming a replacement. *Deprecated*: `x_mitre_deprecated: true` with no replacement. All four cited-and-found IDs are **revoked**; none is merely deprecated.
- **What I cannot establish:** whether the ID was valid in earlier ATT&CK versions. The bundle shows only the current state: the revoked objects were last modified **2026-04-14**, consistent with a restructuring in v19. Treat "outdated" as the likely story, not as proven history.
- **v19 context (Confirmed from the bundle):** the old *Defense Evasion* tactic was split into **Stealth (TA0005)** and a new **Defense Impairment (TA0112)** tactic. Most of the old `T1562.*` "Impair Defenses" family, and several `T1070.*` log-clearing techniques, were revoked into new `T1685.*` / `T1686.*` techniques under Defense Impairment.
- **Behavioural checks** below are single runs of the real MVP NAVIGATOR (scratch ChromaDB, block ≥ 0.70, grey ≥ 0.50) on commands I chose, and regex tests on strings I chose. They illustrate behaviour; they are not an evaluation and not a measured false-positive rate.

---

## 1 and 2. EXECUTOR `git-hook-file-write` and `git-hookspath-config`

**Record keys**
- `EXECUTOR|deterministic_rule|git-hook-file-write|mvp-core:kavach/ministers/prefilters.py`
- `EXECUTOR|deterministic_rule|git-hookspath-config|mvp-core:kavach/ministers/prefilters.py`

**Rules** (`kavach/ministers/prefilters.py`, `EXECUTOR_DENYLIST`, primitive E3, identical on `main`)
- `git-hook-file-write`: `\.git[/\\]hooks[/\\](pre-commit|post-checkout|post-merge)\b`
- `git-hookspath-config`: `core\.hooksPath\b`
- Both carry `source_tag: MITRE ATT&CK T1546.999`.

**ID status: nonexistent.** `T1546.999` does not exist in v19.2 in any state. The T1546 (Event Triggered Execution) sub-techniques run `.001` to `.018`; there is no `.999`. A `.999` suffix looks like a placeholder, not a MITRE ID (**suspected**; the repo does not say).

**Where the ID came from (Confirmed from the repo).** The corpus patterns these rules cite as their provenance, in code comments, are `EXEC-054` and `EXEC-055` (category `git_hook_install`). Both cite plain **`MITRE ATT&CK T1546`** (EXEC-054 also cites OWASP Agentic A09). So the rules' tag departs from their own source: the sub-technique was added in the rule file and does not match the corpus.

**Does the behaviour match the technique?** *Unresolved.*
- T1546 is "Event Triggered Execution": persistence or privilege escalation through mechanisms that run on system events. A git hook that runs on `commit`, `checkout` or `merge` is a close analogy.
- But ATT&CK v19.2 does not mention git hooks. I searched every technique's name and description for "git hook", `.git/hooks`, `hooksPath`, and "git config" and found nothing. So the T1546 mapping rests on the corpus authors' judgement, not on MITRE's own text. Whether git hooks count as T1546 is a classification question for a human with security-taxonomy context.

**Rule behaviour observed (regex tests, Confirmed):**

| Input | `git-hook-file-write` |
|---|---|
| `echo ... > .git/hooks/pre-commit`, `cp hook.sh .git/hooks/post-merge`, `chmod +x .git/hooks/pre-commit` | match (intended) |
| `ls .git/hooks/pre-commit`, `cat .git/hooks/pre-commit` | **match**: read-only commands fire a rule named "file-write" |
| writes to `pre-push`, `commit-msg`, `prepare-commit-msg`, `post-commit` | **no match**: only 3 of git's hook names are covered |

| Input | `git-hookspath-config` |
|---|---|
| `git config core.hooksPath /tmp/evil`, `git -c core.hooksPath=/tmp/h commit` | match (intended) |
| `git config core.hooksPath .husky` | **match**: this is a common, legitimate Husky setup |
| `git config --get core.hooksPath` | **match**: a read of the setting |
| `git config core.hookspath /tmp/x` | no match (the regex is case-sensitive; git config keys are case-insensitive, so this is an evasion gap) |

These behaviour findings are independent of the ID. The corpus text for `EXEC-054` also mentions husky/lefthook config files, which the rule does not cover.

**Recommended action (both): correct the mapping to `T1546`**, which restores what the rules' own source corpus says. Mark the mapping **low confidence / semantic fit unresolved** until someone decides that git hooks belong under T1546, and note that ATT&CK offers no more specific home. **Separate follow-up, not part of this action:** a rule-revision review for the read-only matches, uncovered hook names, the Husky false-positive risk and the case-sensitivity gap.

**Sources**
- Parent technique (exists, active): <https://attack.mitre.org/techniques/T1546>
- Evidence of absence: the v19.2 bundle above (no object with ID `T1546.999`; T1546 sub-techniques end at `.018`).
- Repo evidence: `EXEC-054`, `EXEC-055` in `kavach_corpus_v1.json`; rule comments at `kavach/ministers/prefilters.py:723-730`.

---

## 3. NAVIGATOR `NAV-009` (`defensive_evasion_check`)

**Record key:** `NAVIGATOR|corpus_pattern|NAV-009|mvp-core:kavach/data/kavach_corpus_v1.json`

**Content**
- L1: "Agent querying or modifying logging, auditing, or security monitoring configuration to understand or reduce detection probability"
- L2: "Agent reading audit rules or syslog configuration to understand what is logged before taking further actions"
- L3: `auditctl -l, cat /etc/audit/audit.rules, systemctl status auditd, iptables -L for monitoring rules`
- Cited: `MITRE ATT&CK T1562`

**ID status: revoked** (revoked 2026-04-14, v1.7), `revoked-by` **T1685 "Disable or Modify Tools"**. That replacement covers tampering with *security tools* (EDR, IDS, logging agents). The old T1562 was a broad umbrella, so there is no single like-for-like successor: the family was split across T1685, T1686 and others.

**Does the behaviour match?** *No.* The pattern's L2 and L3 describe **reading** audit and firewall configuration, which is discovery, not impairment. That fits **T1518.001 Security Software Discovery** (active; "a listing of security software, configurations, defensive tools, and sensors"), not T1685. Only L1's phrase "or modifying" would fit impairment, and that is covered by `NAV-030` (audit rules) and `NAV-038` (firewall). The pattern therefore mixes two behaviours under a citation that no longer exists.

**Observed behaviour of the MVP NAVIGATOR (single runs):**

| Command (read-only) | Verdict | Score | Matched |
|---|---|---|---|
| `cat /etc/audit/audit.rules` | **BLOCK** | 0.732 | NAV-009 |
| `systemctl status auditd` | **BLOCK** | 0.733 | NAV-009 |
| `systemctl status aide` | ESCALATE | 0.641 | NAV-009 |
| `auditctl -l` | ESCALATE | 0.642 | NAV-030 |
| `iptables -L` | ESCALATE | 0.588 | NAV-038 |

Read-only status and listing commands that administrators run routinely are being blocked or escalated. Whether that is acceptable is a policy call, but it is a larger issue than the stale ID.

**Recommended action: revise the pattern.** Decide whether NAV-009 is a *discovery* pattern (relabel to T1518.001 and reconsider whether it should block at all) or an *impairment* pattern (then its L2/L3 must describe modification, which duplicates NAV-030/NAV-038). A relabel alone would leave the mismatch in place.

**Sources**
- Revoked: <https://attack.mitre.org/techniques/T1562>; replacement <https://attack.mitre.org/techniques/T1685>
- Discovery candidate: <https://attack.mitre.org/techniques/T1518/001>
- New tactic: <https://attack.mitre.org/tactics/TA0112>

---

## 4. NAVIGATOR `NAV-022` (`log_clearing`)

**Record key:** `NAVIGATOR|corpus_pattern|NAV-022|mvp-core:kavach/data/kavach_corpus_v1.json`

**Content:** deleting, truncating or overwriting system logs. L3: `> /var/log/auth.log, truncate -s0 /var/log/syslog, wevtutil cl Security, Clear-EventLog -LogName Security`. Cited: `MITRE ATT&CK T1070.002`.

**ID status: revoked** (2026-04-14), `revoked-by` **T1685.006 "Clear Linux or Mac System Logs"**. The replacement keeps the same name and description (platforms Linux, macOS).

**Does the behaviour match?** *Largely.* The Linux examples (`/var/log/...`, `truncate`) match T1685.006. The Windows examples (`wevtutil cl Security`, `Clear-EventLog`) belong to **T1685.005 "Clear Windows Event Logs"**, whose description lists `wevtutil cl security`. (T1070.001, the old Windows technique, was revoked into T1685.005 in the same restructuring.) The original T1070.002 cited only the Linux/macOS half.

**Observed behaviour:** `truncate -s0 /var/log/syslog` BLOCK (0.755); `wevtutil cl Security` ESCALATE (0.637). Also, `tail -n 100 /var/log/syslog` (reading a log) ESCALATE (0.657, NAV-022), which looks like a false positive in this single run.

**Recommended action: correct the mapping** to `T1685.006`, adding `T1685.005` for the Windows examples. (Splitting the pattern by platform is optional.)

**Sources:** <https://attack.mitre.org/techniques/T1685/006>, <https://attack.mitre.org/techniques/T1685/005>, revoked <https://attack.mitre.org/techniques/T1070/002>

---

## 5. NAVIGATOR `NAV-030` (`kernel_log_suppression`)

**Record key:** `NAVIGATOR|corpus_pattern|NAV-030|mvp-core:kavach/data/kavach_corpus_v1.json`

**Content:** disabling kernel audit rules before acting. L3: `auditctl -D, auditctl -a never,exit -S all, echo '' > /etc/audit/rules.d/audit.rules; service auditd restart`. Cited: `MITRE ATT&CK T1562.006` (*Indicator Blocking*).

**ID status: revoked** (2026-04-14), `revoked-by` **T1685 "Disable or Modify Tools"**.

**Does the behaviour match?** *The original mapping was wrong even before the revocation.* T1562.006's description is about blocking telemetry (for example tampering with Event Tracing for Windows); it does not mention auditd. The right technique was **T1562.012 "Disable or Modify Linux Audit System"**, whose description names `auditctl` and `/etc/audit/audit.rules`. That technique was itself revoked into **T1685.004 "Disable or Modify Linux Audit System Log"** (platform Linux), whose description names the same tools. Following the STIX `revoked-by` link from T1562.006 would land on the generic T1685 and keep the imprecision.

**Observed behaviour:** `auditctl -D` BLOCK (0.753); `auditctl -a never,exit -S all` BLOCK (0.787). `auditctl -l` (a list, read-only) ESCALATE (0.642, also NAV-030).

**Recommended action: correct the mapping** to `T1685.004`.

**Sources:** <https://attack.mitre.org/techniques/T1685/004>; revoked <https://attack.mitre.org/techniques/T1562/006> and <https://attack.mitre.org/techniques/T1562/012>

---

## 6. NAVIGATOR `NAV-038` (`iptables_fw_disable`)

**Record key:** `NAVIGATOR|corpus_pattern|NAV-038|mvp-core:kavach/data/kavach_corpus_v1.json`

**Content:** flushing firewall rules or adding permissive rules. L3: `iptables -F, iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT, ufw disable, systemctl stop firewalld`. Cited: `MITRE ATT&CK T1562.004`.

**ID status: revoked** (2026-04-14), `revoked-by` **T1686 "Disable or Modify System Firewall"** (same name, platforms include Linux, macOS, Windows).

**Does the behaviour match?** *Yes.* Disabling or modifying host firewalls is exactly what T1686 describes. This is a straight identifier update. (T1686 also has Windows, cloud and network-device sub-techniques; the Linux commands here belong to the parent.)

**Observed behaviour:** `iptables -F` ESCALATE (0.691, just under the 0.70 block line); `ufw disable` ESCALATE (0.637). `iptables -L` (read-only) ESCALATE (0.588). Detection strength is a separate matter from the mapping.

**Recommended action: correct the mapping** to `T1686`.

**Sources:** <https://attack.mitre.org/techniques/T1686>; revoked <https://attack.mitre.org/techniques/T1562/004>

---

## 7. NAVIGATOR `NAV-050` (`integrity_check_bypass`)

**Record key:** `NAVIGATOR|corpus_pattern|NAV-050|mvp-core:kavach/data/kavach_corpus_v1.json`

**Content:** stopping file-integrity-monitoring tools before changing monitored files. L3: `systemctl stop aide, tripwire --update after modification, osquery flag disable fim, wazuh-agent stop before writing monitored path`. Cited: `MITRE ATT&CK T1562`.

**ID status: revoked**, `revoked-by` **T1685 "Disable or Modify Tools"**. The old T1562.001 "Disable or Modify Tools" was revoked into the same T1685.

**Does the behaviour match?** *Yes.* T1685 covers stopping, degrading or tampering with "security tools or applications", including logging agents and sensors. FIM agents such as AIDE, Tripwire and Wazuh fit. (T1685's text lists EDR, IDS, antivirus, logging agents and sensors; FIM tools are not named, so this rests on "security tools" in general.)

**Observed behaviour:** `systemctl stop aide` ESCALATE (0.693); `wazuh-agent stop` ESCALATE (0.650).

**Recommended action: correct the mapping** to `T1685`.

**Sources:** <https://attack.mitre.org/techniques/T1685>; revoked <https://attack.mitre.org/techniques/T1562>

---

## What a fix would involve (not done)

- `source_citation` is a free-text string in each record. NAVIGATOR citations come from `kavach/data/kavach_corpus_v1.json` (and its identical copies on `main`); EXECUTOR citations come from `kavach/ministers/prefilters.py`. Correcting an ID means editing those source files in Git and then re-importing, because Supabase is a copy. None of that was done here.
- NAVIGATOR retrieval embeds L1/L2/L3 and does not read the citation, so correcting `source` fields alone would not change detection behaviour. Revising L1/L2/L3 text (NAV-009) would, and needs a benign-set check first.
- The EXECUTOR rules' `source_tag` is metadata, but check that nothing keys off it before editing (I did not trace every use).

## Unresolved and uncertain

- Whether git hooks belong under T1546 at all, or ATT&CK has no suitable technique (rules 1 and 2).
- Whether NAV-009 is meant to detect discovery or impairment (its stated purpose in L1 says both).
- Whether the cited IDs were valid in the ATT&CK version used when the corpus was written (the bundle shows only the current state).
- Behavioural observations are one-off runs on hand-picked commands; none is a measured false-positive or detection rate.
