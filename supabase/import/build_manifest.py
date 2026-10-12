#!/usr/bin/env python3
"""
Build the minister_definitions manifest from pinned Git refs.

Reads source files straight out of Git (never the working tree), so the result
depends only on the pinned commits. Writes:
    supabase/seed/manifest.jsonl        one record per line
    supabase/seed/manifest_report.json  counts, duplicates, provenance gaps

Nothing is repaired, deduplicated or rewritten: each record keeps the original
structured definition verbatim in `definition`. Python rule tables (regexes,
frozensets) are serialized mechanically: regex -> {"pattern", "flags"},
set -> sorted list, tuple -> list.

Usage: python supabase/import/build_manifest.py
"""
from __future__ import annotations

import hashlib
import importlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import io
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT_DIR = REPO / "supabase" / "seed"

MINISTERS = ("VAULT", "EXECUTOR", "CHANNEL", "NAVIGATOR")

# Refs are resolved to SHAs once per run; source_commit_sha is the last commit
# that touched each file on that ref.
REFS = {"main": "main", "mvp-core": "mvp-core", "origin/navigator-rearch": "origin/navigator-rearch"}


def git(*args: str, binary: bool = False):
    r = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, check=True)
    return r.stdout if binary else r.stdout.decode()


def show(ref: str, path: str) -> str:
    return git("show", f"{ref}:{path}")


def last_commit(ref: str, path: str) -> str:
    return git("log", "-1", "--format=%H", ref, "--", path).strip()


def canonical_hash(obj) -> str:
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def jsonable(x):
    if isinstance(x, re.Pattern):
        return {"pattern": x.pattern, "flags": x.flags}
    if isinstance(x, (set, frozenset)):
        return sorted((jsonable(i) for i in x), key=lambda v: json.dumps(v, sort_keys=True))
    if isinstance(x, (tuple, list)):
        return [jsonable(i) for i in x]
    if isinstance(x, dict):
        return {str(k): jsonable(v) for k, v in x.items()}
    return x


_TECH_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?|CWE-\d+|CVE-\d{4}-\d+|A\d{2}(?::\d{4})?)\b")
_URL_RE = re.compile(r"https?://[^\s)\]>\"']+")


def technique_ids(citation):
    if not citation:
        return []
    return sorted(set(_TECH_RE.findall(citation)))


class Builder:
    def __init__(self):
        self.records = []
        self.keys = Counter()
        self.tmp = Path(tempfile.mkdtemp(prefix="kavach_manifest_"))
        self.refsha = {r: git("rev-parse", ref).strip() for r, ref in REFS.items()}

    # -- record construction -------------------------------------------------
    def add(self, *, minister, dtype, did, definition, ref, path, origin, context=None,
            l1=None, l2=None, l3=None, category=None, citation=None, notes=None, extra_flags=()):
        assert minister in MINISTERS, minister
        flags = list(extra_flags)
        citation = citation.strip() if isinstance(citation, str) and citation.strip() else None
        urls = _URL_RE.findall(citation) if citation else []
        url = urls[0] if len(urls) == 1 else None
        tids = technique_ids(citation)
        if citation is None:
            flags.append("source_citation_missing")
        elif not tids and not urls:
            flags.append("source_citation_unstructured")
        if url is None:
            flags.append("source_url_unknown")
        flags.append("source_license_unknown")
        base = f"{minister}|{dtype}|{did}|{ref}:{path}"
        self.keys[base] += 1
        key = base if self.keys[base] == 1 else f"{base}|dup{self.keys[base]}"
        if self.keys[base] > 1:
            flags.append("duplicate_id_in_source")
        self.records.append({
            "record_key": key,
            "minister": minister,
            "definition_type": dtype,
            "definition_id": did,
            "l1_intent": l1, "l2_mechanism": l2, "l3_surface": l3,
            "category": category,
            "source_citation": citation,
            "technique_ids": tids,
            "source_url": url,
            "source_license": None,
            "definition": definition,
            "context": context or {},
            "repo_path": path,
            "git_ref": ref,
            "source_commit_sha": last_commit(self.refsha[ref], path),
            "content_hash": canonical_hash(definition),
            "origin_status": origin,
            "provenance_flags": sorted(set(flags)),
            "notes": notes,
        })

    # -- module import from a pinned ref ---------------------------------------
    def import_pkg(self, ref: str, pkg_dir: str, module: str):
        """Extract `pkg_dir` at `ref` into a temp dir and import `module` from it."""
        dest = self.tmp / ref.replace("/", "_")
        if not (dest / pkg_dir).exists():
            raw = git("archive", self.refsha[ref], pkg_dir, binary=True)
            tarfile.open(fileobj=io.BytesIO(raw)).extractall(dest)
        for m in [m for m in sys.modules if m.split(".")[0] == pkg_dir]:
            del sys.modules[m]
        sys.path.insert(0, str(dest))
        try:
            return importlib.import_module(module)
        finally:
            sys.path.remove(str(dest))


def corpus_patterns(b: Builder):
    """kavach_corpus_v1.json (live), ORIGINAL and CHECKPOINT copies."""
    live_main = json.loads(show("main", "kavach_corpus_v1.json"))
    live_mvp = json.loads(show("mvp-core", "kavach/data/kavach_corpus_v1.json"))
    same = canonical_hash(live_main) == canonical_hash(live_mvp)

    def file_ctx(c, **kw):
        return {"corpus_version": c.get("version"), "corpus_description": c.get("description"), **kw}

    for m in ("EXECUTOR", "VAULT", "CHANNEL", "NAVIGATOR"):
        for idx, p in enumerate(live_mvp[m]["patterns"]):
            if m == "NAVIGATOR":
                ref, path, origin, c = "mvp-core", "kavach/data/kavach_corpus_v1.json", "current_mvp", live_mvp
                also = {"main:kavach_corpus_v1.json": "identical file content" if same else "DIFFERS"}
                note = "Loaded at runtime by the MVP NAVIGATOR minister."
            else:
                ref, path, origin, c = "main", "kavach_corpus_v1.json", "legacy_main", live_main
                p = live_main[m]["patterns"][idx]
                also = {"mvp-core:kavach/data/kavach_corpus_v1.json": "carried in the MVP file but not loaded at runtime" if same else "DIFFERS"}
                note = "Used by the legacy cosine path on main; not loaded by the MVP."
            b.add(minister=m, dtype="corpus_pattern", did=p["id"], definition=p, ref=ref, path=path,
                  origin=origin, context=file_ctx(c, also_present_in=also), l1=p.get("L1_intent"),
                  l2=p.get("L2_mechanism"), l3=p.get("L3_surface"), category=p.get("category"),
                  citation=p.get("source"), notes=note)

    for ref_file, status, note in (
        ("kavach_corpus_v1_ORIGINAL.json", "historical", "Earlier copy of the v1 corpus (archived as superseded)."),
        ("kavach_corpus_v1_CHECKPOINT_20260710.json", "historical", "Checkpoint copy of the v1 corpus."),
    ):
        c = json.loads(show("main", ref_file))
        for m in ("EXECUTOR", "VAULT", "CHANNEL", "NAVIGATOR"):
            for p in c[m]["patterns"]:
                b.add(minister=m, dtype="corpus_pattern", did=p["id"], definition=p, ref="main", path=ref_file,
                      origin=status, context=file_ctx(c), l1=p.get("L1_intent"), l2=p.get("L2_mechanism"),
                      l3=p.get("L3_surface"), category=p.get("category"), citation=p.get("source"), notes=note)

    tech = json.loads(show("main", "kavach_corpus_technical.json"))
    for m in MINISTERS:
        for p in tech[m]:
            b.add(minister=m, dtype="corpus_pattern", did=p["id"], definition=p, ref="main",
                  path="kavach_corpus_technical.json", origin="legacy_main",
                  context=file_ctx(tech, collection=tech["collections"].get(m)),
                  l1=p.get("L1_intent"), l2=p.get("L2_mechanism"), l3=p.get("L3_surface"),
                  category=p.get("category"), citation=p.get("source"),
                  notes="Technical-precision corpus. The legacy server can load it, but corpus_loader.py has that call commented out; the MVP does not load it.")


def corpus_candidates(b: Builder):
    for f in sorted(x for x in git("ls-tree", "-r", "--name-only", "main", "corpus_v2/").split() if x.endswith(".json")):
        c = json.loads(show("main", f))
        ctx = {k: v for k, v in c.items() if k != "patterns"}
        for p in c["patterns"]:
            b.add(minister=c["minister"], dtype="corpus_pattern", did=p["id"], definition=p, ref="main", path=f,
                  origin="candidate", context=ctx, l1=p.get("L1_intent"), l2=p.get("L2_mechanism"),
                  l3=p.get("L3_surface"), category=p.get("category"), citation=p.get("source"),
                  notes="Expansion batch written for corpus v2; not merged into kavach_corpus_v1.json.")

    ov = "kavach_eval/reference_corpus_v0/proposed_minister_v0/overnight_v1/"
    f = ov + "navigator_candidates_v0/navigator_candidates_v0.json"
    for p in json.loads(show("main", f)):
        b.add(minister="NAVIGATOR", dtype="corpus_pattern", did=p["id"], definition=p, ref="main", path=f,
              origin="candidate", context={"status": "first-pass candidate batch, staged for review, not merged"},
              l1=p.get("L1_intent"), l2=p.get("L2_mechanism"), l3=p.get("L3_surface"),
              category=p.get("category"), citation=p.get("source"))

    f = "kavach_eval/reference_corpus_v0/proposed_corpus_additions_v0.json"
    c = json.loads(show("main", f))
    ctx = {k: v for k, v in c.items() if k != "proposals"}
    for p in c["proposals"]:
        b.add(minister=p["minister"], dtype="corpus_pattern", did=p["id"], definition=p, ref="main", path=f,
              origin="candidate", context=ctx, l1=p.get("L1_intent"), l2=p.get("L2_mechanism"),
              l3=p.get("L3_surface"), category=p.get("category"),
              citation=p.get("source") or None,
              notes="PROPOSAL ONLY on main. The original object embeds the InjecAgent source-case detail it was derived from; kept verbatim.")

    f = "kavach_eval/reference_corpus_v0/proposed_minister_v0/patterns.json"
    c = json.loads(show("main", f))
    p = c["channel_addition"]
    b.add(minister="CHANNEL", dtype="corpus_pattern", did=p["id"], definition=p, ref="main", path=f,
          origin="candidate", context={"status": c["status"]}, l1=p.get("L1_intent"), l2=p.get("L2_mechanism"),
          l3=p.get("L3_surface"), category=p.get("category"), citation=p.get("source"),
          notes="CHANNEL addition from the STEWARD proposal file. The STEWARD patterns in that file are excluded (STEWARD is out of scope). Embeds source-case detail; kept verbatim.")


def rule_records(b: Builder):
    mvp = b.import_pkg("mvp-core", "kavach", "kavach.ministers.prefilters")
    mainp = b.import_pkg("main", "parliament", "parliament.prefilters")
    prim_mvp = getattr(mvp, "RULE_PRIMITIVE", {})
    ineligible = sorted(getattr(mvp, "SHORT_CIRCUIT_INELIGIBLE_RULE_NAMES", []))
    for minister, attr, path_mvp, path_main in (
        ("VAULT", "VAULT_PATTERNS", "kavach/ministers/prefilters.py", "parliament/prefilters.py"),
        ("EXECUTOR", "EXECUTOR_DENYLIST", "kavach/ministers/prefilters.py", "parliament/prefilters.py"),
    ):
        main_by_name = {n: jsonable(rx) for n, rx, _ in getattr(mainp, attr)}
        for name, rx, src in getattr(mvp, attr):
            d = {"name": name, "pattern": rx.pattern, "flags": rx.flags, "source_tag": src}
            same = main_by_name.get(name) == jsonable(rx)
            b.add(minister=minister, dtype="deterministic_rule", did=name, definition=d, ref="mvp-core",
                  path=path_mvp, origin="current_mvp", citation=src,
                  context={"list": attr, "primitive": prim_mvp.get(name),
                           "also_present_in": {"main:" + path_main: "identical rule" if same else "DIFFERS or absent"}},
                  notes="Deterministic rule used at request time by the MVP.")

    # Proposed (unmerged) rules
    f = "kavach_eval/reference_corpus_v0/proposed_minister_v0/overnight_v1/PROPOSED_vault_executor_expansion.py"
    src = show("main", f)
    ns = {}
    exec(compile(src, f, "exec"), ns)  # module only imports `re` and defines tables
    live_names = {m: {n for n, _, _ in getattr(mvp, a)} for m, a in (("VAULT", "VAULT_PATTERNS"), ("EXECUTOR", "EXECUTOR_DENYLIST"))}
    for var, val in ns.items():
        if var.startswith("PROPOSED_") and isinstance(val, list):
            minister = "VAULT" if "VAULT" in var else "EXECUTOR" if "EXECUTOR" in var else None
            if minister is None:
                continue
            for name, rx, tag in val:
                d = {"name": name, "pattern": rx.pattern, "flags": rx.flags, "source_tag": tag}
                b.add(minister=minister, dtype="deterministic_rule", did=name, definition=d, ref="main", path=f,
                      origin="experimental", citation=tag,
                      context={"list": var, "name_also_in_current_mvp_rules": name in live_names[minister],
                               "status": "PROPOSED, NOT WIRED IN, NOT MERGED"},
                      notes="source_tag here names the inspiring corpus pattern ID(s), not an ATT&CK/CWE tag.")

    # Parser-level patterns the MVP minister logic depends on
    sp = b.import_pkg("mvp-core", "kavach", "kavach.ministers.struct_parse")
    sp_main = b.import_pkg("main", "parliament", "parliament.struct_parse")
    vault_consts = ("_CRED_PATH_STRONG", "_CRED_EXT", "_CRED_GLOB_RE")
    exec_consts = ("_URL_RE", "_REMOTE_HOST_RE", "_WRITE_FLAG_RE", "_REDIRECT_RE", "_REDIRECT_TARGET_RE",
                   "_DISK_WRITE_METHOD_RE", "_EXECUTABLE_TARGET_RE", "_PIPE_TO_INTERPRETER_RE",
                   "_BENIGN_CAPABLE_FETCH_TOOL_RE")
    for minister, names in (("VAULT", vault_consts), ("EXECUTOR", exec_consts)):
        for n in names:
            d = jsonable(getattr(sp, n))
            same = jsonable(getattr(sp_main, n, None)) == d
            b.add(minister=minister, dtype="parser_pattern", did=n, definition=d, ref="mvp-core",
                  path="kavach/ministers/struct_parse.py", origin="current_mvp",
                  context={"also_present_in": {"main:parliament/struct_parse.py": "identical" if same else "DIFFERS"}},
                  extra_flags=["source_citation_missing"],
                  notes="Structural-parser regex behind the minister's fallback check.")
    pf = mvp
    for n in ("_AST_DANGEROUS_CALLS", "_AST_SUBPROCESS_FUNCS"):
        d = jsonable(getattr(pf, n))
        same = jsonable(getattr(mainp, n, None)) == d
        b.add(minister="EXECUTOR", dtype="parser_pattern", did=n, definition=d, ref="mvp-core",
              path="kavach/ministers/prefilters.py", origin="current_mvp",
              context={"also_present_in": {"main:parliament/prefilters.py": "identical" if same else "DIFFERS"}},
              extra_flags=["source_citation_missing"], notes="AST import-alias resolution tables.")


def channel_records(b: Builder):
    ct = b.import_pkg("mvp-core", "kavach", "kavach.ministers.channel_taint")
    ct_main = b.import_pkg("main", "parliament", "parliament.channel_taint")
    P, PM = "kavach/ministers/channel_taint.py", "main:parliament/channel_taint.py"

    def also(name):
        return {PM: "identical" if jsonable(getattr(ct_main, name, None)) == jsonable(getattr(ct, name)) else "DIFFERS"}

    for tool in sorted(ct.SOURCE_TOOLS_EXACT):
        b.add(minister="CHANNEL", dtype="channel_source_tool", did=tool, definition={"tool": tool}, ref="mvp-core",
              path=P, origin="current_mvp", extra_flags=["source_citation_missing"],
              context={"constant": "SOURCE_TOOLS_EXACT", "also_present_in": also("SOURCE_TOOLS_EXACT")})
    for tool, keys in ct.DESTINATION_TOOLS.items():
        b.add(minister="CHANNEL", dtype="channel_destination_tool", did=tool,
              definition={"tool": tool, "argument_keys": list(keys)}, ref="mvp-core", path=P,
              origin="current_mvp", extra_flags=["source_citation_missing"],
              context={"constant": "DESTINATION_TOOLS", "also_present_in": also("DESTINATION_TOOLS")})
    for name, dtype in (
        ("SOURCE_TOOL_PATTERN", "channel_source_rule"), ("_SOURCE_VERB_TOKENS", "channel_source_rule"),
        ("_SENSITIVE_NOUN_TOKENS", "channel_source_rule"), ("_SENSITIVE_NOUN_BIGRAMS", "channel_source_rule"),
        ("DESTINATION_ALLOWLIST", "channel_behavior"), ("_EMAIL_DESTINATION_TOOLS", "channel_behavior"),
        ("_EMAIL_RE", "channel_behavior"), ("_IBAN_RE", "channel_behavior"),
        ("_PHONE_RE", "channel_behavior"), ("_URL_RE", "channel_behavior"),
    ):
        b.add(minister="CHANNEL", dtype=dtype, did=name, definition=jsonable(getattr(ct, name)), ref="mvp-core",
              path=P, origin="current_mvp", extra_flags=["source_citation_missing"],
              context={"also_present_in": also(name)})


def navigator_records(b: Builder):
    # MVP constants
    nav = b.import_pkg("mvp-core", "kavach", "kavach.ministers.navigator")
    b.add(minister="NAVIGATOR", dtype="threshold_config", did="mvp-navigator-thresholds",
          definition={"thresholds": nav.THRESHOLDS, "top_k": nav.TOP_K, "embed_model": nav.EMBED_MODEL,
                      "query_prefix": nav.QUERY_PREFIX},
          ref="mvp-core", path="kavach/ministers/navigator.py", origin="current_mvp",
          extra_flags=["source_citation_missing"], notes="Constants hard-coded in the MVP NAVIGATOR.")

    # Experimental: authflow observational/consequential taxonomy
    af = b.import_pkg("main", "parliament", "parliament.navigator_authflow")
    for n in ("OBSERVATIONAL_TOOLS", "CONSEQUENTIAL_TOOLS", "AMBIGUOUS_TOOLS",
              "_OBSERVATIONAL_VERB_TOKENS", "_CONSEQUENTIAL_VERB_TOKENS"):
        b.add(minister="NAVIGATOR", dtype="navigator_authflow_taxonomy", did=n, definition=jsonable(getattr(af, n)),
              ref="main", path="parliament/navigator_authflow.py", origin="experimental",
              extra_flags=["source_citation_missing"],
              notes="NAVIGATOR authflow experiment (pieces 1-2 only); not part of the MVP.")

    # Experimental: sensitivity tiers on a side branch
    tiers = b.import_pkg("origin/navigator-rearch", "parliament", "parliament.navigator_tiers")
    for n in ("TIER_3_TOOLS_FINANCIAL", "TIER_3_TOOLS_PHYSICAL", "TIER_3_TOOLS_ACCOUNT_SECURITY"):
        b.add(minister="NAVIGATOR", dtype="navigator_tier_rule", did=n, definition=jsonable(getattr(tiers, n)),
              ref="origin/navigator-rearch", path="parliament/navigator_tiers.py", origin="experimental",
              extra_flags=["source_citation_missing"], notes="Deterministic TIER_3 tool list on the navigator-rearch branch.")
    b.add(minister="NAVIGATOR", dtype="navigator_tier_rule", did="_TIER_3_REGEXES",
          definition=jsonable(tiers._TIER_3_REGEXES), ref="origin/navigator-rearch",
          path="parliament/navigator_tiers.py", origin="experimental", extra_flags=["source_citation_missing"])
    b.add(minister="NAVIGATOR", dtype="threshold_config", did="TIER_FLOOR_CONFIDENCE",
          definition={"TIER_FLOOR_CONFIDENCE": tiers.TIER_FLOOR_CONFIDENCE}, ref="origin/navigator-rearch",
          path="parliament/navigator_tiers.py", origin="experimental", extra_flags=["source_citation_missing"])


def description_and_threshold_records(b: Builder):
    cfg = json.loads(show("main", "kavach_router_config.json"))
    for m in MINISTERS:
        b.add(minister=m, dtype="minister_description", did=f"{m}-router-scope", definition=cfg["routing_corpus"][m],
              ref="main", path="kavach_router_config.json", origin="legacy_main",
              context={"router_config_version": cfg.get("version"), "router_config_description": cfg.get("description")},
              extra_flags=["source_citation_missing"],
              notes="Domain-boundary descriptions used by the legacy semantic router (not an attack corpus). "
                    + ("Text refers to session trajectory, which the MVP excludes." if m == "NAVIGATOR" else ""))
    import yaml
    c = yaml.safe_load(show("main", "parliament/config.yaml"))
    th = c["thresholds"]
    for m in MINISTERS:
        b.add(minister=m, dtype="threshold_config", did=f"{m}-legacy-threshold",
              definition={"per_minister_block": th["per_minister"][m], "global_block": th["block"], "global_grey": th["grey"]},
              ref="main", path="parliament/config.yaml", origin="legacy_main", extra_flags=["source_citation_missing"],
              notes="Assembled from config.yaml thresholds.per_minister / block / grey.")


def report(b: Builder) -> dict:
    recs = b.records
    by = lambda f: dict(sorted(Counter(f(r) for r in recs).items()))
    hash_groups = defaultdict(list)
    for r in recs:
        hash_groups[(r["minister"], r["definition_type"], r["content_hash"])].append(r["record_key"])
    dup_content = {"|".join(k[:2]) + "|" + k[2][:12]: v for k, v in hash_groups.items() if len(v) > 1}
    dup_id = defaultdict(list)
    for r in recs:
        dup_id[(r["minister"], r["definition_type"], r["definition_id"])].append(r["record_key"])
    flags = Counter(f for r in recs for f in r["provenance_flags"])
    return {
        "total_records": len(recs),
        "pinned_refs": b.refsha,
        "by_minister": by(lambda r: r["minister"]),
        "by_definition_type": by(lambda r: r["definition_type"]),
        "by_origin_status": by(lambda r: r["origin_status"]),
        "by_minister_type_origin": by(lambda r: f'{r["minister"]}/{r["definition_type"]}/{r["origin_status"]}'),
        "provenance_flag_counts": dict(sorted(flags.items())),
        "records_missing_source_citation": sum("source_citation_missing" in r["provenance_flags"] for r in recs),
        "records_unstructured_source_citation": sum("source_citation_unstructured" in r["provenance_flags"] for r in recs),
        "records_with_source_url": sum(r["source_url"] is not None for r in recs),
        "records_with_license": sum(r["source_license"] is not None for r in recs),
        "ids_appearing_in_more_than_one_source": sum(1 for k, v in dup_id.items() if len(v) > 1 and k[2]),
        "identical_content_across_records": {"groups": len(dup_content), "records_involved": sum(len(v) for v in dup_content.values())},
        "duplicate_ids_within_one_source": [r["record_key"] for r in recs if "duplicate_id_in_source" in r["provenance_flags"]],
    }


def main():
    b = Builder()
    corpus_patterns(b)
    corpus_candidates(b)
    rule_records(b)
    channel_records(b)
    navigator_records(b)
    description_and_threshold_records(b)
    keys = [r["record_key"] for r in b.records]
    assert len(keys) == len(set(keys)), "record_key collision"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_DIR / "manifest.jsonl", "w", encoding="utf-8") as f:
        for r in sorted(b.records, key=lambda r: r["record_key"]):
            f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
    rep = report(b)
    (OUT_DIR / "manifest_report.json").write_text(json.dumps(rep, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: rep[k] for k in ("total_records", "by_minister", "by_definition_type", "by_origin_status")}, indent=2))


if __name__ == "__main__":
    main()
