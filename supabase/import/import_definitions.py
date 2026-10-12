#!/usr/bin/env python3
"""
Idempotently upsert supabase/seed/manifest.jsonl into public.minister_definitions,
then verify the remote contents against the manifest.

Credentials: SUPABASE_DB_URL (a Postgres connection string) from the environment.
It is never read from a file in the repo and never printed. Use the project's
database connection string from the Supabase dashboard (Project Settings >
Database), or a local disposable Postgres.

Upsert rules: every column is refreshed from the manifest EXCEPT review_status,
created_at and id, so a later review is never overwritten by a re-import.

Usage:
    SUPABASE_DB_URL=... python supabase/import/import_definitions.py [--dry-run] [--expect-empty]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

MANIFEST = Path(__file__).resolve().parents[1] / "seed" / "manifest.jsonl"

COLS = ["record_key", "minister", "definition_type", "definition_id", "l1_intent", "l2_mechanism",
        "l3_surface", "category", "source_citation", "technique_ids", "source_url", "source_license",
        "provenance_flags", "definition", "context", "repo_path", "git_ref", "source_commit_sha",
        "content_hash", "origin_status", "notes"]
JSONB = {"definition", "context"}

UPSERT = (
    f"insert into public.minister_definitions ({', '.join(COLS)}) values ({', '.join(['%s'] * len(COLS))}) "
    "on conflict (record_key) do update set "
    + ", ".join(f"{c} = excluded.{c}" for c in COLS if c != "record_key")
    + ", imported_at = now()"
)


def load_manifest():
    recs = [json.loads(l) for l in MANIFEST.read_text(encoding="utf-8").splitlines() if l.strip()]
    keys = [r["record_key"] for r in recs]
    if len(keys) != len(set(keys)):
        sys.exit("manifest has duplicate record_keys")
    return recs


def row(r):
    return tuple(Jsonb(r[c]) if c in JSONB else r[c] for c in COLS)


def counts(recs, keyf):
    return dict(sorted(Counter(keyf(r) for r in recs).items()))


def verify(cur, recs) -> bool:
    ok = True
    cur.execute("select count(*) from public.minister_definitions")
    remote_total = cur.fetchone()[0]
    print(f"remote rows: {remote_total}  manifest records: {len(recs)}")
    ok &= remote_total == len(recs)
    for label, col, keyf in (
        ("minister", "minister", lambda r: r["minister"]),
        ("definition_type", "definition_type", lambda r: r["definition_type"]),
        ("origin_status", "origin_status", lambda r: r["origin_status"]),
    ):
        cur.execute(f"select {col}, count(*) from public.minister_definitions group by 1 order by 1")
        remote = dict(cur.fetchall())
        local = counts(recs, keyf)
        match = remote == local
        ok &= match
        print(f"by {label}: {'OK' if match else 'MISMATCH'}  {remote}")
        if not match:
            print(f"   manifest: {local}")
    # Content integrity: every manifest hash present for its key
    cur.execute("select record_key, content_hash from public.minister_definitions")
    remote_hash = dict(cur.fetchall())
    bad = [r["record_key"] for r in recs if remote_hash.get(r["record_key"]) != r["content_hash"]]
    print(f"content_hash mismatches: {len(bad)}")
    ok &= not bad
    cur.execute("select review_status, count(*) from public.minister_definitions group by 1")
    print("review_status:", dict(cur.fetchall()))
    cur.execute("select count(*) from public.minister_definitions where source_citation is null")
    print("rows with NULL source_citation:", cur.fetchone()[0],
          "(manifest:", sum(r["source_citation"] is None for r in recs), ")")
    cur.execute("select count(*) from public.minister_definitions where source_url is null")
    print("rows with NULL source_url:", cur.fetchone()[0])
    cur.execute("select count(*) from public.minister_definitions where source_license is null")
    print("rows with NULL source_license:", cur.fetchone()[0])
    return bool(ok)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="validate the manifest and connection; write nothing")
    ap.add_argument("--expect-empty", action="store_true", help="abort unless the table is empty before importing")
    args = ap.parse_args()

    url = os.environ.get("SUPABASE_DB_URL")
    if not url:
        sys.exit("SUPABASE_DB_URL is not set (see supabase/import/README.md)")
    recs = load_manifest()
    print(f"manifest: {len(recs)} records")
    with psycopg.connect(url) as conn:
        cur = conn.cursor()
        cur.execute("select count(*) from public.minister_definitions")
        before = cur.fetchone()[0]
        print(f"remote rows before: {before}")
        if args.expect_empty and before:
            sys.exit("table is not empty; aborting (--expect-empty)")
        if args.dry_run:
            print("dry run: nothing written")
            return
        cur.executemany(UPSERT, [row(r) for r in recs])
        conn.commit()
        ok = verify(cur, recs)
    print("VERIFIED" if ok else "VERIFICATION FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
