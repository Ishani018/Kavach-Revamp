#!/usr/bin/env python3
"""
Phase A conversion: prepare candidate test data from three public sources.

  1. RedCode-Exec  - the 600 bash scripts                      (MIT)
  2. tldr-pages    - a targeted sample of security-adjacent examples (CC BY 4.0)
  3. nebius/SWE-agent-trajectories - single-line shell commands from a fixed 100-trajectory sample (CC BY 4.0)

What it does: reads the sources, keeps every original value verbatim, derives a wire-format tool call by a
stated rule, and records deterministic flags (placeholders, incomplete commands, duplicates, overlap with data we
already hold). It does NOT execute any command (the only parsing is bashlex, which builds a syntax tree), does NOT
run the Kavach MVP, and does NOT classify anything as malicious or benign. Labels are the sources' own meanings and
are marked unreviewed.

Output goes to this folder only. Nothing here is registered in evaluation/registry.json and nothing here is held out.

    python build_phase_a.py --redcode PATH --tldr PATH [--extra-reference DIR]

    --redcode  checkout of github.com/AI-secure/RedCode at the pinned commit
    --tldr     checkout of github.com/tldr-pages/tldr at the pinned commit (pages/{common,linux,osx} needed)
    --extra-reference  optional directory holding a checkout of Kavach's `main` branch, used to widen the
               duplicate/overlap check (training pairs and the legacy corpora live only there)
"""
import argparse
import hashlib
import importlib.util
import json
import random
import re
import subprocess
import sys
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BUILD_VERSION = "1.0"

REDCODE = {"name": "RedCode-Exec (bash)", "repo": "https://github.com/AI-secure/RedCode",
           "commit": "c84b6db88fd8bd258e29f12e692ccfd4287a454d", "licence": "MIT", "licence_path": "LICENSE"}
TLDR = {"name": "tldr-pages", "repo": "https://github.com/tldr-pages/tldr",
        "commit": "3b04259a58d0bfecaa31c3179b3d349a81ef7893", "licence": "CC BY 4.0", "licence_path": "LICENSE.md"}
SWE = {"name": "nebius/SWE-agent-trajectories", "repo": "https://huggingface.co/datasets/nebius/SWE-agent-trajectories",
       "commit": "68195a1450865274106246d0d0296a1d6807b88e", "licence": "CC BY 4.0 (cc-by-4.0 per the dataset card)",
       "licence_path": "README.md"}

# ---- selection configuration (all choices are explicit and recorded in the manifest) -------------
TLDR_SEED = 20261015
TLDR_PLATFORMS = ("common", "linux", "osx")        # Windows pages excluded: shell is ambiguous
TLDR_FAMILIES = {
    "credentials_keys": {"quota": 40, "names": "gpg gpg2 ssh-keygen ssh-add ssh-agent ssh-copy-id openssl age pass sops ansible-vault htpasswd passwd chpasswd keytool security op vault bw lpass certbot step keyctl kinit".split(),
                         "prefixes": ["aws-secretsmanager", "aws-sts", "aws-iam", "git-credential", "gh-auth", "gpg-", "openssl-", "ssh-"]},
    "network_transfer": {"quota": 40, "names": "curl wget scp rsync sftp ftp nc ncat socat ssh telnet netcat aria2c rclone mosh tftp http xh lftp smbclient mc s3cmd gsutil".split(),
                         "prefixes": ["aws-s3"]},
    "recon_sniff": {"quota": 30, "names": "nmap masscan tcpdump tshark dig nslookup host whois traceroute mtr arp netstat ss lsof ip ifconfig ngrep nikto whatweb ping fping arp-scan nbtscan enum4linux snmpwalk".split(),
                    "prefixes": []},
    "privilege_exec": {"quota": 45, "names": "sudo su doas chmod chown chgrp setcap getcap visudo systemctl service crontab at launchctl nohup bash sh zsh xargs env nsenter unshare chroot strace ltrace gdb docker podman kubectl eval exec watch timeout".split(),
                       "prefixes": ["docker-", "podman-", "kubectl-", "systemctl-"]},
    "destructive_storage": {"quota": 25, "names": "rm dd shred mkfs wipefs fdisk parted truncate srm cryptsetup mount umount losetup sgdisk badblocks rmdir unlink".split(), "prefixes": ["mkfs."]},
    "logging_defense": {"quota": 20, "names": "journalctl logrotate auditctl ausearch iptables ufw firewall-cmd nft fail2ban-client setenforce getenforce sestatus aa-status apparmor_parser history logger dmesg".split(), "prefixes": []},
}
SWE_OFFSETS = list(range(0, 80000, 8000))     # 10 windows x 10 trajectories = 100 trajectories
SWE_WINDOW = 10
SWE_BUILTINS = {"edit", "open", "goto", "scroll_up", "scroll_down", "search_file", "search_dir", "find_file", "create", "submit", "openurl"}

SPLIT_SALT = "phase-a-split-v1"
SPLIT_DIAGNOSIS_PERCENT = 60   # the rest is RESERVED: nobody tunes or diagnoses on it
NEAR_DUP = 0.9           # within a source
NEAR_REF = 0.8           # against data we already hold


# ---- helpers ---------------------------------------------------------------------------------------
def sha256(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def norm(s):
    return re.sub(r"\s+", " ", s.lower()).strip()


def toks(s):
    return frozenset(re.findall(r"[a-z0-9_./\-$]{2,}", s.lower()))


def jac(a, b):
    return len(a & b) / len(a | b) if a | b else 0.0


def run(*a, cwd=None):
    return subprocess.run(a, cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def wire(tool, command):
    return f"tool:{tool} args:{json.dumps({'command': command})}", json.dumps({"command": command})


def bash_parses(cmd):
    """Parse-only syntax check (builds a syntax tree; nothing is run)."""
    try:
        import bashlex
        bashlex.parse(cmd)
        return True
    except Exception:
        return False


def check_head(repo, meta):
    head = run("git", "rev-parse", "HEAD", cwd=repo)
    if head != meta["commit"]:
        sys.exit(f"{meta['name']}: checkout is at {head}, expected pinned {meta['commit']}")


# ---- 1. RedCode ----------------------------------------------------------------------------------
def redcode_items(repo):
    d = repo / "dataset" / "RedCode-Exec" / "bash2text_dataset_json"
    items = []
    for f in sorted(d.glob("*.json"), key=lambda p: int(re.search(r"index(\d+)_", p.name).group(1))):
        rel = f.relative_to(repo).as_posix()
        blob = run("git", "rev-parse", f"{REDCODE['commit']}:{rel}", cwd=repo)
        for pos, r in enumerate(json.loads(f.read_text(encoding="utf-8"))):
            code = r["Code"]
            call, args = wire("bash", code)
            flags = []
            if "\n" in code.strip(): flags.append("multi_line")
            if code.lstrip().startswith("#!"): flags.append("has_shebang")
            if len(code) > 1500: flags.append("very_long")
            if re.search(r"127\.0\.0\.1|localhost", code): flags.append("depends_on_local_service")
            if re.search(r"(/etc/|/root/|/usr/|/home/|/var/|/tmp/)", code): flags.append("depends_on_filesystem_state")
            if not bash_parses(code): flags.append("bashlex_cannot_parse")
            if r.get("Language") != "bash": flags.append("language_not_bash")
            items.append(dict(
                item_id=None, batch="phase-a", source_key="redcode",
                source=dict(dataset=REDCODE["name"], repo=REDCODE["repo"], pinned_version=REDCODE["commit"], licence=REDCODE["licence"],
                            licence_url=f"{REDCODE['repo']}/blob/{REDCODE['commit']}/{REDCODE['licence_path']}",
                            source_file=rel, source_file_git_blob=blob, source_item_id=r["Index"],
                            source_location=f"record {pos} of {rel}", scenario_index=r["Index"].split("_")[0],
                            permalink=f"{REDCODE['repo']}/blob/{REDCODE['commit']}/{rel}"),
                original={k: r[k] for k in ("Index", "Prompt", "Language", "Code", "expected_result", "Text_summary", "Text_details") if k in r},
                command=code,
                label=dict(source_label_meaning="risky_by_scenario_design (unreviewed): RedCode-Exec files this script under a risky scenario. It does not by itself prove the script is harmful in every setting, and the severity differs between scenarios. The scenario index is the only risk descriptor the files give; scenario names were not found in the files read.",
                           status="unreviewed"),
                transformation=dict(rule="tool 'bash'; arguments {\"command\": <the Code field, unchanged>}", tool="bash", args_json=args, call=call),
                flags=flags))
    return items


# ---- 2. tldr -----------------------------------------------------------------------------------------
def tldr_pool(repo):
    fam_of = {}
    for plat in TLDR_PLATFORMS:
        for f in sorted((repo / "pages" / plat).glob("*.md")):
            name = f.stem
            for fam, cfg in TLDR_FAMILIES.items():
                if name in cfg["names"] or any(name.startswith(p) for p in cfg["prefixes"]):
                    fam_of[(plat, name)] = fam
                    break
    pool = []
    for (plat, name), fam in sorted(fam_of.items()):
        path = f"pages/{plat}/{name}.md"
        blob = run("git", "rev-parse", f"{TLDR['commit']}:{path}", cwd=repo)
        n, desc = 0, None
        for ln, line in enumerate((repo / path).read_text(encoding="utf-8").splitlines(), 1):
            if line.startswith("- "):
                desc = line[2:].rstrip(":")
            elif line.startswith("`") and line.endswith("`") and len(line) > 2:
                n += 1
                orig = line[1:-1]
                trans = re.sub(r"\{\{(.*?)\}\}", r"\1", orig)
                flags = []
                if "{{" in orig: flags.append("placeholders_replaced")
                if re.search(r"\[-[^\]]*\|[^\]]*\]|\[--", orig): flags.append("option_syntax_not_literal")
                if "..." in orig: flags.append("contains_ellipsis")
                if plat == "common": flags.append("shell_unspecified")
                if not bash_parses(trans): flags.append("bashlex_cannot_parse")
                call, args = wire("bash", trans)
                pool.append(dict(
                    item_id=None, batch="phase-a", source_key="tldr", family=fam,
                    source=dict(dataset=TLDR["name"], repo=TLDR["repo"], pinned_version=TLDR["commit"], licence=TLDR["licence"],
                                licence_url=f"{TLDR['repo']}/blob/{TLDR['commit']}/{TLDR['licence_path']}",
                                source_file=path, source_file_git_blob=blob, source_item_id=f"{plat}/{name}#{n}",
                                source_location=f"line {ln}", permalink=f"{TLDR['repo']}/blob/{TLDR['commit']}/{path}?plain=1#L{ln}"),
                    original=dict(command=orig, example_description=desc, page=name, platform=plat),
                    command=trans,
                    label=dict(source_label_meaning="documented_legitimate_usage (unreviewed): an example from the tldr-pages community cheat sheet for '%s'. It does not by itself prove the command is harmless in every context." % name,
                               status="unreviewed"),
                    transformation=dict(rule="tool 'bash'; arguments {\"command\": <original with each {{placeholder}} replaced by its inner text>}", tool="bash", args_json=args, call=call),
                    flags=flags))
    return pool


def tldr_select(pool):
    """Stratified, seeded sample. Notation fragments ('[-a|--all]', '...') are excluded from the sample but listed."""
    excluded, eligible = [], defaultdict(list)
    for it in pool:
        bad = [f for f in it["flags"] if f in ("option_syntax_not_literal", "contains_ellipsis", "bashlex_cannot_parse")]
        if bad:
            excluded.append(dict(source_item_id=it["source"]["source_item_id"], reason=",".join(bad)))
        else:
            eligible[it["family"]].append(it)
    rng = random.Random(TLDR_SEED)
    chosen = []
    for fam, cfg in TLDR_FAMILIES.items():
        cand = sorted(eligible[fam], key=lambda x: x["source"]["source_item_id"])
        chosen += rng.sample(cand, min(cfg["quota"], len(cand)))
    chosen.sort(key=lambda x: (x["family"], x["source"]["source_item_id"]))
    return chosen, excluded


# ---- 3. SWE-agent trajectories --------------------------------------------------------------------
def fetch_json(url):
    for attempt in range(3):
        try:
            return json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "kavach-phase-a"}), timeout=120))
        except Exception:
            if attempt == 2:
                raise


def swe_items():
    rev = fetch_json("https://huggingface.co/api/datasets/nebius/SWE-agent-trajectories")["sha"]
    if rev != SWE["commit"]:
        sys.exit(f"SWE-agent dataset revision is {rev}, expected pinned {SWE['commit']}")
    items, excluded, traj = [], Counter(), 0
    excl_rows = []
    for off in SWE_OFFSETS:
        d = fetch_json(f"https://datasets-server.huggingface.co/rows?dataset=nebius%2FSWE-agent-trajectories&config=default&split=train&offset={off}&length={SWE_WINDOW}")
        for r in d["rows"]:
            traj += 1
            row, row_idx = r["row"], r["row_idx"]
            for ti, m in enumerate(row["trajectory"]):
                if m["role"] != "ai":
                    continue
                text = m["text"] or ""
                blocks = re.findall(r"```(?:[a-z]*)\n(.*?)\n```", text, re.S)
                sid = f"{row['instance_id']}|{row['model_name']}|row{row_idx}|turn{ti}"
                if not blocks:
                    excluded["no_command_block"] += 1; excl_rows.append(dict(source_item_id=sid, reason="no_command_block")); continue
                cmd = blocks[-1].strip()
                first = cmd.split()[0] if cmd.split() else ""
                if first in SWE_BUILTINS:
                    excluded["agent_builtin_command"] += 1; excl_rows.append(dict(source_item_id=sid, reason="agent_builtin_command")); continue
                if "\n" in cmd or len(cmd) >= 400:
                    excluded["multi_line_or_long"] += 1; excl_rows.append(dict(source_item_id=sid, reason="multi_line_or_long")); continue
                flags = []
                if re.match(r"^(open|edit|goto|create|search_dir|search_file|find_file)\S", cmd): flags.append("malformed_builtin_like")
                if not bash_parses(cmd): flags.append("bashlex_cannot_parse")
                if re.match(r"^cd\b", cmd): flags.append("depends_on_working_directory")
                if re.search(r"https?://", cmd): flags.append("contains_url")
                call, args = wire("bash", cmd)
                items.append(dict(
                    item_id=None, batch="phase-a", source_key="swe",
                    source=dict(dataset=SWE["name"], repo=SWE["repo"], pinned_version=SWE["commit"], licence=SWE["licence"],
                                licence_url=f"{SWE['repo']}/blob/{SWE['commit']}/README.md",
                                source_file="default/train", source_file_git_blob=None, source_item_id=sid,
                                source_location=f"row {row_idx}, trajectory turn {ti}",
                                permalink=f"https://datasets-server.huggingface.co/rows?dataset=nebius%2FSWE-agent-trajectories&config=default&split=train&offset={row_idx}&length=1",
                                instance_id=row["instance_id"], model_name=row["model_name"], resolved=row["target"]),
                    original=dict(command=cmd, turn_text_sha256=sha256(text)),
                    command=cmd,
                    label=dict(source_label_meaning="agent_generated_assumed_benign (unreviewed): a command an SWE-agent model issued while working on a GitHub issue. The dataset carries no safety label; 'benign' is an assumption, and the model's commands are not guaranteed harmless.",
                               status="unreviewed"),
                    transformation=dict(rule="tool 'bash'; arguments {\"command\": <the last fenced block of the agent turn, whitespace-trimmed>}", tool="bash", args_json=args, call=call),
                    flags=flags))
    return items, excluded, excl_rows, traj


# ---- reference sets for overlap ---------------------------------------------------------------------------
def flatten(v, out):
    if isinstance(v, dict):
        for x in v.values(): flatten(x, out)
    elif isinstance(v, list):
        for x in v: flatten(x, out)
    elif v is not None:
        out.append(str(v))


def call_values(text):
    m = re.match(r"tool:(\S+)\s+args:(\{.*\})\s*$", text.strip(), re.S)
    if not m:
        return [text]
    try:
        out = []; flatten(json.loads(m.group(2)), out); return out
    except Exception:
        return [text]


def build_reference(extra):
    ref = []   # (source, string)
    add = lambda src, s: ref.append((src, s.strip())) if s and s.strip() else None
    J = lambda p: [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    ev = ROOT / "evaluation" / "datasets"
    for src, rel in (("kavach_pb_attack", "kavach_pb_attack/_kavach_pb_attack_checkpoint.json"),
                     ("kavach_pb_bfcl", "kavach_pb_bfcl_benign/_kavach_pb_bfcl_general_purpose_checkpoint.json"),
                     ("benign_v0", "benign_v0_agent_shaped/_kavach_pb_benign_v0_agent_shaped_checkpoint.json")):
        for v in json.loads((ev / rel).read_text()).values():
            for s in call_values(v["call_text"]): add(src, s)
    for r in J(ev / "atriumos" / "atriumos_scenarios.jsonl"):
        for c in r["calls"]:
            for s in call_values(c): add("atriumos", s)
    for r in J(ev / "openclaw_native" / "attack_scenarios.jsonl"):
        for s in call_values(r["text"]): add("openclaw", s)
    for r in json.loads((ROOT / "tests" / "data" / "real_benign_trajectories.json").read_text()):
        for c in r["calls"]:
            o = []; flatten(c["args"], o)
            for s in o: add("real_benign", s)
    for p in (ROOT / "kavach" / "data" / "kavach_corpus_v1.json",):
        d = json.loads(p.read_text())
        for m in ("EXECUTOR", "VAULT", "CHANNEL", "NAVIGATOR"):
            for pat in d[m]["patterns"]:
                for l in ("L1_intent", "L2_mechanism", "L3_surface"): add("corpus_v1", pat[l])
    for r in J(ROOT / "review" / "heldout-candidates-batch-1" / "review_items.jsonl"):
        add("batch1", json.loads(r["transformed_args_json"])["command"] if isinstance(r, dict) else "")
    if extra:
        for p in sorted(Path(extra).glob("kavach_eval/reference_corpus_v0/training_pairs_*.jsonl")):
            for r in J(p):
                for s in call_values(r["call_text"]): add("training_pairs", s)
                if r.get("raw_command"): add("training_pairs", r["raw_command"])
        tech = Path(extra) / "kavach_corpus_technical.json"
        if tech.exists():
            d = json.loads(tech.read_text())
            for m in ("EXECUTOR", "VAULT", "CHANNEL", "NAVIGATOR"):
                for pat in d[m]:
                    for l in ("L1_intent", "L2_mechanism", "L3_surface"): add("corpus_technical", pat[l])
    return ref


class Overlap:
    def __init__(self, ref):
        self.ref = ref
        self.exact = defaultdict(set)
        for src, s in ref:
            self.exact[norm(s)].add(src)
        self.t = [toks(s) for _, s in ref]
        df = Counter(x for ts in self.t for x in ts)
        self.inv = defaultdict(list)
        for i, ts in enumerate(self.t):
            for x in ts:
                if df[x] <= len(self.t) * 0.02:
                    self.inv[x].append(i)

    def check(self, s):
        n = norm(s)
        if n in self.exact:
            return {"kind": "exact", "sources": sorted(self.exact[n])}
        ts = toks(s)
        if len(ts) < 3:
            return None
        cnt = Counter()
        for x in ts:
            for i in self.inv.get(x, ()):
                cnt[i] += 1
        best, src = 0.0, None
        for i, _ in cnt.most_common(40):
            j = jac(ts, self.t[i])
            if j > best:
                best, src = j, self.ref[i][0]
        return {"kind": "near", "jaccard": round(best, 2), "sources": [src]} if best >= NEAR_REF else None


def within_source_duplicates(items):
    """Mark non-representatives. Representative = first item in source order."""
    seen = {}
    t = []
    for it in items:
        key = (it["transformation"]["tool"], norm(it["command"]))
        if key in seen:
            it["duplicate_of"] = {"item_id": seen[key], "kind": "exact"}
        else:
            seen[key] = it["item_id"]
            it["duplicate_of"] = None
    reps = [it for it in items if it["duplicate_of"] is None]
    tk = {it["item_id"]: toks(it["command"]) for it in reps}
    for i, a in enumerate(reps):
        if a["duplicate_of"]:
            continue
        for b in reps[i + 1:]:
            if b["duplicate_of"] or len(tk[a["item_id"]]) < 4:
                continue
            if jac(tk[a["item_id"]], tk[b["item_id"]]) >= NEAR_DUP:
                b["duplicate_of"] = {"item_id": a["item_id"], "kind": "near"}
    # a representative can itself be marked near-duplicate later: point every duplicate at the final root
    by_id = {it["item_id"]: it for it in items}
    for it in items:
        d, kind = it["duplicate_of"], None
        while d and by_id[d["item_id"]]["duplicate_of"]:
            nxt = by_id[d["item_id"]]["duplicate_of"]
            kind = "near" if "near" in (d["kind"], nxt["kind"]) else "exact"
            d = {"item_id": nxt["item_id"], "kind": kind}
        it["duplicate_of"] = d


def assign_splits(items):
    """Deterministic diagnosis/reserved split by hash of the item id. A duplicate always follows its
    representative, so near-identical commands cannot sit on both sides of the split."""
    by_id = {it["item_id"]: it for it in items}
    for it in items:
        rep = it
        while rep.get("duplicate_of"):
            rep = by_id[rep["duplicate_of"]["item_id"]]
        h = int(sha256(SPLIT_SALT + rep["item_id"])[:8], 16) % 100
        it["split"] = "diagnosis" if h < SPLIT_DIAGNOSIS_PERCENT else "reserved"


def load_triage_indicators():
    spec = importlib.util.spec_from_file_location("tp", ROOT / "review" / "heldout-candidates-batch-1" / "triage_pipeline.py")
    tp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tp)
    return tp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--redcode", required=True, type=Path)
    ap.add_argument("--tldr", required=True, type=Path)
    ap.add_argument("--extra-reference", type=Path)
    ap.add_argument("--out", type=Path, default=HERE)
    a = ap.parse_args()
    check_head(a.redcode, REDCODE); check_head(a.tldr, TLDR)

    red = redcode_items(a.redcode)
    pool = tldr_pool(a.tldr)
    tl, tl_excluded = tldr_select(pool)
    swe, swe_excl, swe_excl_rows, n_traj = swe_items()

    blocks = [("PA-R", red), ("PA-T", tl), ("PA-S", swe)]
    for prefix, items in blocks:
        for i, it in enumerate(items, 1):
            it["item_id"] = f"{prefix}-{i:04d}"
        within_source_duplicates(items)
        assign_splits(items)

    ov = Overlap(build_reference(a.extra_reference))
    tp = load_triage_indicators()
    hints_out = []
    for _, items in blocks:
        for it in items:
            o = ov.check(it["command"])
            it["overlap_with_data_we_hold"] = o
            if o: it["flags"].append("overlaps_data_we_hold")
            if it["duplicate_of"]: it["flags"].append("duplicate_in_source")
            hits = tp.indicators(it["command"])
            sev = max(({"high": 3, "medium": 2, "low": 1}[h["severity"]] for h in hits), default=0)
            concern = None
            if it["source_key"] == "redcode" and sev == 0:
                concern = "scenario label says risky but no risk indicator matched the script text; severity unclear"
            if it["source_key"] == "tldr" and sev == 3:
                concern = "documented as legitimate, but the command has a high-risk surface"
            if it["source_key"] == "swe" and sev >= 2:
                concern = "assumed-benign agent command with a medium/high-risk surface: skim before use"
            it["uncertain_label"] = bool(concern)
            it["uncertain_label_reason"] = concern
            it["original_sha256"] = sha256(json.dumps(it["original"], sort_keys=True, ensure_ascii=False))
            it["call_sha256"] = sha256(it["transformation"]["call"])
            hints_out.append(dict(item_id=it["item_id"], status="automated_hint_not_verified",
                                  indicators=hits, max_severity={0: "none", 1: "low", 2: "medium", 3: "high"}[sev],
                                  uncertain_label=bool(concern), uncertain_label_reason=concern,
                                  note="Text-pattern hint from the batch-1 triage catalogue. Not a label. That catalogue was tuned on batch 1, so recall on new data is unknown."))
            it["flags"] = sorted(set(it["flags"]))

    files = {}
    for fname, items in (("redcode_bash_items.jsonl", red), ("tldr_security_items.jsonl", tl), ("swe_agent_items.jsonl", swe)):
        with open(a.out / fname, "w", encoding="utf-8") as fh:
            for it in items:
                row = {k: v for k, v in it.items() if k not in ("family",)}
                row["selection_family"] = it.get("family")
                fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        files[fname] = sha256((a.out / fname).read_text(encoding="utf-8"))
    for fname, rows in (("phase_a_hints.jsonl", hints_out),
                        ("tldr_excluded_from_sample.jsonl", tl_excluded),
                        ("swe_agent_excluded.jsonl", swe_excl_rows)):
        with open(a.out / fname, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
        files[fname] = sha256((a.out / fname).read_text(encoding="utf-8"))

    def stats(items):
        fl = Counter(f for it in items for f in it["flags"])
        return dict(items=len(items), flags=dict(sorted(fl.items())),
                    duplicates_in_source=Counter((it["duplicate_of"] or {}).get("kind", "none") for it in items),
                    overlap_with_data_we_hold=Counter((it["overlap_with_data_we_hold"] or {}).get("kind", "none") for it in items),
                    uncertain_label=sum(it["uncertain_label"] for it in items))
    st = {"redcode": stats(red), "tldr": stats(tl), "swe": stats(swe)}
    for v in st.values():
        v["duplicates_in_source"] = dict(v["duplicates_in_source"]); v["overlap_with_data_we_hold"] = dict(v["overlap_with_data_we_hold"])
    st["tldr"]["pool_before_sampling"] = len(pool)
    st["tldr"]["pool_by_family"] = dict(Counter(p["family"] for p in pool))
    st["tldr"]["excluded_notation_or_unparseable"] = len(tl_excluded)
    st["tldr"]["sample_by_family"] = dict(Counter(it["family"] for it in tl))
    st["swe"]["trajectories_sampled"] = n_traj
    st["swe"]["excluded_commands"] = dict(swe_excl)
    for key, items in (("redcode", red), ("tldr", tl), ("swe", swe)):
        st[key]["split"] = dict(Counter(it["split"] for it in items))
    st["redcode"]["scenarios"] = len({it["source"]["scenario_index"] for it in red})
    manifest = {
        "batch_id": "phase-a-candidates", "build_version": BUILD_VERSION,
        "status": "candidate_unreviewed", "held_out_status": "not_verified", "in_evaluation_registry": False,
        "do_not_use_for": "any detection, precision, recall, false-positive or accuracy claim",
        "executed_any_example": False, "ran_kavach_mvp": False,
        "sources": [REDCODE, TLDR, SWE],
        "config": {"tldr_seed": TLDR_SEED, "tldr_platforms": TLDR_PLATFORMS,
                   "tldr_families": {k: {"quota": v["quota"], "names": v["names"], "prefixes": v["prefixes"]} for k, v in TLDR_FAMILIES.items()},
                   "swe_offsets": SWE_OFFSETS, "swe_window": SWE_WINDOW, "swe_builtins": sorted(SWE_BUILTINS),
                   "split_salt": SPLIT_SALT, "split_diagnosis_percent": SPLIT_DIAGNOSIS_PERCENT,
                   "near_duplicate_within_source": NEAR_DUP, "near_duplicate_vs_held_data": NEAR_REF},
        "overlap_reference": {"strings": len(ov.ref), "by_source": dict(Counter(s for s, _ in ov.ref)),
                              "extra_reference_used": bool(a.extra_reference)},
        "stats": st, "files": files,
    }
    (a.out / "phase_a_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True, default=list) + "\n", encoding="utf-8")
    print(json.dumps({k: v["items"] for k, v in st.items()}))


if __name__ == "__main__":
    main()
