#!/usr/bin/env python3
"""
NAVIGATOR escalation diagnosis (read-only; nothing in the MVP is changed).

Question: why does NAVIGATOR return ESCALATE for so many ordinary benign commands?

Method: re-compute NAVIGATOR's hybrid score step by step (dense BGE similarity, BM25, RRF selection, lexical gate)
from the MVP's own index and embedding function, check the re-computation against the real minister, and then
decompose the scores. A set of "what-if" variants is computed arithmetically on cached similarities. The what-ifs
are DIAGNOSTIC ONLY.

Data discipline:
  * Only Phase A items with split == "diagnosis" are read. Items with split == "reserved" are never loaded, so they
    stay available to confirm any future change.
  * The existing development sets (BFCL benign, Kavach-PB attack) are used as additional descriptive material. They
    overlap with rule development and are NOT independent evidence.
  * Nothing here selects a threshold or a setting. Results describe where scores come from; they are not a tuned
    configuration and must not be quoted as performance.

    python diagnose_navigator.py [--chroma-path DIR] [--out FILE]
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

from kavach.ministers import retrieval as R                       # noqa: E402
from kavach.ministers.navigator import (NavigatorMinister, QUERY_PREFIX, THRESHOLDS, TOP_K)  # noqa: E402
from kavach.schemas import ToolCall                                # noqa: E402

GRID = (0.5, 0.55, 0.6, 0.65, 0.7)       # thresholds shown for description only


def wire(cmd, tool="bash"):
    return f"tool:{tool} args:{json.dumps({'command': cmd})}"


def load_diagnosis_items():
    """Phase A items, diagnosis split only, one per duplicate cluster."""
    sets = {}
    for fname, key in (("tldr_security_items.jsonl", "benign_tldr"), ("swe_agent_items.jsonl", "benign_swe"),
                       ("redcode_bash_items.jsonl", "attack_redcode")):
        rows = [json.loads(l) for l in (HERE / fname).read_text(encoding="utf-8").splitlines() if l.strip()]
        rows = [r for r in rows if r["split"] == "diagnosis" and r["duplicate_of"] is None]
        assert all(r["split"] == "diagnosis" for r in rows)
        sets[key] = [(r["item_id"], r["transformation"]["call"], r["command"]) for r in rows]
    return sets


def load_dev_sets():
    ev = ROOT / "evaluation" / "datasets"
    bf = json.loads((ev / "kavach_pb_bfcl_benign" / "_kavach_pb_bfcl_general_purpose_checkpoint.json").read_text())
    pb = json.loads((ev / "kavach_pb_attack" / "_kavach_pb_attack_checkpoint.json").read_text())
    cmd = lambda t: (json.loads(re.match(r"tool:\S+\s+args:(\{.*\})\s*$", t, re.S).group(1)) or {}) if t else {}
    return {"dev_benign_bfcl": [(k, v["call_text"], "") for k, v in bf.items()],
            "dev_attack_pb": [(k, v["call_text"], "") for k, v in pb.items()]}


class Explainer:
    def __init__(self, nav):
        self.nav = nav
        col = nav._collection
        got = col.get(include=["embeddings", "documents", "metadatas"])
        self.ids = got["ids"]
        self.E = np.asarray(got["embeddings"], dtype=np.float32)
        self.docs = got["documents"]
        self.meta = got["metadatas"]
        self.level = [m["level"] for m in self.meta]
        self.pid = [m["pattern_id"] for m in self.meta]
        bm = nav._bm25
        self.bm25 = bm["bm25"]
        self.bm_pos = {i: p for p, i in enumerate(bm["ids"])}
        self.bm_to_chroma = np.array([self.bm_pos[i] for i in self.ids])      # chroma row -> bm25 position
        self.doc_tokens = [set(R._tokenize(d)) for d in bm["docs"]]
        self.floor = R._GATE_FLOOR

    def embed(self, text, prefix=True):
        m = self.nav._model
        v = m.encode((QUERY_PREFIX if prefix else "") + text, normalize_embeddings=True, show_progress_bar=False)
        return np.asarray(v, dtype=np.float32)

    def score(self, text, q=None, docs_mask=None, gate_floor=None, use_gate=True, tokens_text=None):
        """Mirror of retrieval.run_minister_hybrid. docs_mask restricts which documents exist (what-if)."""
        q = self.embed(text) if q is None else q
        sims_all = np.maximum(0.0, self.E @ q)
        idx = np.arange(len(self.ids)) if docs_mask is None else np.flatnonzero(docs_mask)
        order = idx[np.argsort(-sims_all[idx], kind="stable")][:TOP_K]
        toks = R._tokenize(text if tokens_text is None else tokens_text)
        bm_all = self.bm25.get_scores(toks)                       # indexed by BM25 position
        pos_of = np.array([self.bm_pos[i] for i in self.ids])      # chroma row -> BM25 position
        bm_by_chroma = bm_all[pos_of]
        pool = np.arange(len(self.ids)) if docs_mask is None else idx
        # exactly as retrieval.py: ascending argsort, then reversed (so ties are ranked in reverse index order)
        pool_pos = pos_of[pool]
        ranked_pos = pool_pos[np.argsort(bm_all[pool_pos])[::-1]]
        rank_of_pos = {int(p): r for r, p in enumerate(ranked_pos)}
        glob_rank = {int(c): rank_of_pos[int(pos_of[c])] for c in pool}
        dense_order = list(order)
        bm_order = sorted(dense_order, key=lambda c: glob_rank[int(c)])
        fused = {}
        for r, c in enumerate(dense_order): fused[c] = fused.get(c, 0) + 1 / (R._RRF_K + r + 1)
        for r, c in enumerate(bm_order): fused[c] = fused.get(c, 0) + 1 / (R._RRF_K + r + 1)
        best = sorted(fused.items(), key=lambda kv: kv[1], reverse=True)[0][0]     # same tie-breaking as _rrf_fuse
        # sensitivity probe: how often would a different (stable, ascending-index) BM25 tie order pick a different document?
        alt_ranked = pool_pos[np.argsort(-bm_all[pool_pos], kind="stable")]
        alt_rank = {int(p): r for r, p in enumerate(alt_ranked)}
        bm_order_alt = sorted(dense_order, key=lambda c: alt_rank[int(pos_of[c])])
        fused_alt = {}
        for r, c in enumerate(dense_order): fused_alt[c] = fused_alt.get(c, 0) + 1 / (R._RRF_K + r + 1)
        for r, c in enumerate(bm_order_alt): fused_alt[c] = fused_alt.get(c, 0) + 1 / (R._RRF_K + r + 1)
        best_alt = sorted(fused_alt.items(), key=lambda kv: kv[1], reverse=True)[0][0]
        dense_sel = float(sims_all[best])
        qmax = float(np.max(bm_by_chroma[pool])) if len(pool) else 0.0
        bm_sel = float(bm_by_chroma[best])
        fl = self.floor if gate_floor is None else gate_floor
        if qmax <= 1e-9: gate = fl
        else: gate = fl + (1.0 - fl) * min(1.0, max(0.0, bm_sel) / qmax)
        final = min(1.0, dense_sel * gate) if use_gate else min(1.0, dense_sel)
        top1 = int(order[0])
        return dict(final=final, dense_sel=dense_sel, gate=gate, qmax=qmax, bm_sel=bm_sel, best=int(best), top1=top1, best_alt_tiebreak=int(best_alt), bm_sel_is_zero=(float(bm_sel) <= 1e-9),
                    top1_sim=float(sims_all[top1]), sel_is_dense_top1=(int(best) == top1),
                    sel_is_bm25_top=(float(bm_sel) >= qmax - 1e-12 and qmax > 0), query_tokens=toks)


def q(a):
    a = np.asarray(a, dtype=float)
    return {k: round(float(np.quantile(a, v)), 3) for k, v in (("p10", .1), ("p25", .25), ("median", .5), ("p75", .75), ("p90", .9), ("max", 1.0))} if len(a) else {}


def auc(attack, benign):
    """P(random attack score > random benign score), ties count half. 0.5 = no separation."""
    a, b = np.asarray(attack, float), np.asarray(benign, float)
    if not len(a) or not len(b): return None
    gt = (a[:, None] > b[None, :]).mean()
    eq = (a[:, None] == b[None, :]).mean()
    return round(float(gt + 0.5 * eq), 3)


def share_at(a, ths=GRID):
    a = np.asarray(a, dtype=float)
    return {str(t): round(float((a >= t).mean()), 3) for t in ths} if len(a) else {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chroma-path", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=HERE / "navigator_diagnosis_results.json")
    a = ap.parse_args()
    nav = NavigatorMinister(chroma_path=a.chroma_path)
    ex = Explainer(nav)
    sets = {**load_diagnosis_items(), **load_dev_sets()}
    out = {"status": "diagnostic_only_not_evidence_of_performance",
           "mvp_thresholds": THRESHOLDS, "gate_floor": ex.floor, "top_k": TOP_K,
           "corpus": {"patterns": len(set(ex.pid)), "documents": len(ex.ids), "by_level": dict(Counter(ex.level))},
           "sets": {k: len(v) for k, v in sets.items()},
           "data_policy": "Phase A items with split=reserved are never read. dev_* sets overlap with rule development: descriptive only."}

    # 1. fidelity: does the re-computation match the real minister?
    mism, checked = [], 0
    for key, rows in sets.items():
        for iid, call, _ in rows[:60]:
            r = ex.score(call, tokens_text=call)
            real = nav.check(ToolCall.model_validate({"text": call, "session_id": "diag"}))
            checked += 1
            if abs(round(r["final"], 4) - (real.confidence or 0)) > 1e-3:
                mism.append((key, iid, round(r["final"], 4), real.confidence))
    out["fidelity"] = {"checked": checked, "mismatches": len(mism), "examples": mism[:5],
                       "note": "Chroma's approximate nearest-neighbour search can differ from the exact search used here"}

    # 2. score components per set
    comp, per_item = {}, {}
    for key, rows in sets.items():
        res = []
        for iid, call, cmd in rows:
            r = ex.score(call, tokens_text=call)
            r["id"], r["call"] = iid, call
            res.append(r)
        per_item[key] = res
        f = [r["final"] for r in res]
        comp[key] = dict(n=len(res), final=q(f), share_ge=share_at(f),
                         dense_selected=q([r["dense_sel"] for r in res]), dense_top1=q([r["top1_sim"] for r in res]),
                         gate=q([r["gate"] for r in res]),
                         gate_at_floor=round(float(np.mean([abs(r["gate"] - ex.floor) < 1e-9 for r in res])), 3),
                         selected_is_dense_top1=round(float(np.mean([r["sel_is_dense_top1"] for r in res])), 3),
                         selected_has_top_bm25=round(float(np.mean([r["sel_is_bm25_top"] for r in res])), 3),
                         selected_has_zero_bm25=round(float(np.mean([r["bm_sel_is_zero"] for r in res])), 3),
                         selection_changes_with_other_tie_order=round(float(np.mean([r["best"] != r["best_alt_tiebreak"] for r in res])), 3))
    out["components"] = comp
    f = lambda k, key="final": [r[key] for r in per_item[k]]
    out["separability_auc"] = {
        "phaseA_diagnosis_attack_redcode_vs_benign(tldr+swe)": {"final_score": auc(f("attack_redcode"), f("benign_tldr") + f("benign_swe")),
                                                                  "dense_only": auc(f("attack_redcode", "dense_sel"), f("benign_tldr", "dense_sel") + f("benign_swe", "dense_sel"))},
        "development_only_pb_attack_vs_bfcl_benign (NOT independent)": {"final_score": auc(f("dev_attack_pb"), f("dev_benign_bfcl")),
                                                                         "dense_only": auc(f("dev_attack_pb", "dense_sel"), f("dev_benign_bfcl", "dense_sel"))},
        "reading": "0.5 means the score does not separate the two groups at all; 1.0 means perfect separation."}
    with open(HERE / "navigator_diagnosis_items.jsonl", "w", encoding="utf-8") as fh:
        for k, rows in per_item.items():
            for r in rows:
                fh.write(json.dumps({"set": k, "id": r["id"], "final": round(r["final"], 4), "dense_selected": round(r["dense_sel"], 4),
                                     "gate": round(r["gate"], 4), "selected_doc": ex.ids[r["best"]], "bm25_selected": round(r["bm_sel"], 3)}) + "\n")

    # 3. decomposition of benign escalations (score >= grey)
    grey = THRESHOLDS["grey"]
    ben = per_item["benign_tldr"] + per_item["benign_swe"]
    esc = [r for r in ben if r["final"] >= grey]
    dense_only_esc = [r for r in ben if r["dense_sel"] >= grey]
    out["benign_escalation"] = {
        "n_benign": len(ben), "n_escalated": len(esc), "share": round(len(esc) / len(ben), 3),
        "of_escalated_dense_selected": q([r["dense_sel"] for r in esc]),
        "of_escalated_gate": q([r["gate"] for r in esc]),
        "would_escalate_with_dense_alone": len(dense_only_esc),
        "escalated_where_gate_is_floor": sum(abs(r["gate"] - ex.floor) < 1e-9 for r in esc),
        "escalated_where_dense_below_0.6": sum(r["dense_sel"] < 0.6 for r in esc),
        "escalated_where_dense_below_0.7": sum(r["dense_sel"] < 0.7 for r in esc),
        "reading": "final = dense_selected x gate and the gate is at most 1, so any ESCALATE needs dense_selected >= the grey threshold. If dense similarity between unrelated texts is already near that value, the threshold cannot separate."}

    # 4. which documents win, and with which words
    win = Counter(); win_lvl = Counter(); tok_hits = Counter()
    for r in esc:
        win[ex.pid[r["best"]]] += 1; win_lvl[ex.level[r["best"]]] += 1
        for t in set(r["query_tokens"]) & ex.doc_tokens[ex.bm_pos[ex.ids[r["best"]]]]: tok_hits[t] += 1
    cat = {m["pattern_id"]: m["category"] for m in ex.meta}
    out["winners_among_benign_escalations"] = {
        "distinct_patterns": len(win), "top": [(p, cat[p], n) for p, n in win.most_common(10)],
        "share_of_top5": round(sum(n for _, n in win.most_common(5)) / max(1, len(esc)), 3), "by_level": dict(win_lvl),
        "query_tokens_shared_with_winning_doc": tok_hits.most_common(15)}
    # per-doc "hubness" over all benign diagnosis queries
    hub = Counter(ex.ids[r["best"]] for r in ben)
    out["hub_documents"] = [(i, cat[i.split("_")[0]], n) for i, n in hub.most_common(8)]

    # 5. noise floor: what do unrelated texts score?
    empties = [wire(""), wire("", "sh"), wire("", "powershell"), "tool:read_file args:{}", 'tool:get_weather args:{"city": "Paris"}']
    out["wrapper_only_scores"] = {t: {"final": round(ex.score(t, tokens_text=t)["final"], 3), "dense": round(ex.score(t, tokens_text=t)["dense_sel"], 3)} for t in empties}
    rng = np.random.default_rng(20261016)
    qs = [ex.embed(c) for _, _, c in [x for x in sets["benign_tldr"]][:100]]
    pair = [float(qs[i] @ qs[j]) for i, j in zip(rng.integers(0, len(qs), 300), rng.integers(0, len(qs), 300)) if i != j]
    q2d = np.maximum(0, np.stack(qs) @ ex.E.T)
    out["noise_floor"] = {"cosine_between_unrelated_benign_queries": q(pair),
                          "cosine_benign_query_vs_all_300_docs": q(q2d.ravel()),
                          "max_over_300_docs_per_query": q(q2d.max(axis=1)),
                          "reading": "BGE similarity is compressed upward: unrelated texts already score high, and taking the MAXIMUM over 300 documents pushes it higher still."}

    # 6. exploratory what-ifs (diagnostic only): benign escalation share vs attack catch share
    def var(name, **kw):
        rows = {}
        for key in ("benign_tldr", "benign_swe", "attack_redcode", "dev_benign_bfcl", "dev_attack_pb"):
            sc = []
            for iid, call, cmd in sets[key]:
                text = kw.get("text_fn", lambda c, cm: c)(call, cmd)
                qv = ex.embed(text, prefix=kw.get("prefix", True)) if ("text_fn" in kw or "prefix" in kw) else None
                s = ex.score(text, q=qv, docs_mask=kw.get("mask"), gate_floor=kw.get("floor"), use_gate=kw.get("gate", True), tokens_text=text)
                sc.append(s["final"])
            rows[key] = sc
        ben = rows["benign_tldr"] + rows["benign_swe"]
        return dict(variant=name, benign_phaseA_diag=dict(n=len(ben), escalate_or_block=round(float((np.array(ben) >= grey).mean()), 3), block=round(float((np.array(ben) >= .7).mean()), 3)),
                    attack_redcode_diag=dict(n=len(rows["attack_redcode"]), escalate_or_block=round(float((np.array(rows["attack_redcode"]) >= grey).mean()), 3), block=round(float((np.array(rows["attack_redcode"]) >= .7).mean()), 3)),
                    dev_benign_bfcl=dict(escalate_or_block=round(float((np.array(rows["dev_benign_bfcl"]) >= grey).mean()), 3)),
                    dev_attack_pb=dict(escalate_or_block=round(float((np.array(rows["dev_attack_pb"]) >= grey).mean()), 3), block=round(float((np.array(rows["dev_attack_pb"]) >= .7).mean()), 3)))
    levels = np.array(ex.level)
    out["what_if_exploratory"] = [
        var("baseline (as shipped)"),
        var("dense score only (gate off)", gate=False),
        var("gate floor 0.5", floor=0.5),
        var("gate floor 0.8", floor=0.8),
        var("only L3 documents", mask=(levels == "L3_surface")),
        var("only L1 documents", mask=(levels == "L1_intent")),
        var("only L2 documents", mask=(levels == "L2_mechanism")),
        var("query = command text only (no tool:/args: wrapper)", text_fn=lambda c, cm: cm if cm else c),
        var("query without the BGE instruction prefix", prefix=False),
    ]
    out["what_if_note"] = "Exploratory, computed on the diagnosis split and development sets. Do not choose a setting from this table: any candidate must be confirmed on the reserved split and independent data."

    # 7. threshold sensitivity (description only)
    out["threshold_sensitivity"] = {k: share_at([r["final"] for r in v]) for k, v in per_item.items()}
    out["per_item_scores_file"] = None
    a.out.write_text(json.dumps(out, indent=1, sort_keys=True, default=float) + "\n", encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("fidelity", "benign_escalation")}, indent=1, default=float))


if __name__ == "__main__":
    main()
