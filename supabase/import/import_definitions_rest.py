#!/usr/bin/env python3
"""
REST variant of import_definitions.py, for when only the project URL and a
secret (service-role) API key are available instead of a Postgres connection string.

Same manifest, same idempotent upsert on record_key, same --expect-empty guard and
verification. review_status/id/created_at are not sent, so re-imports never overwrite
a review. Credentials come from the environment only and are never printed:
    SUPABASE_URL         https://<ref>.supabase.co
    SUPABASE_SECRET_KEY  sb_secret_...   (server-side only)

Usage: python supabase/import/import_definitions_rest.py [--dry-run] [--expect-empty]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from import_definitions import COLS, load_manifest, counts  # noqa: E402  (psycopg import is unused here)

BATCH = 150


def call(method, path, body=None, headers=None):
    url = os.environ["SUPABASE_URL"].rstrip("/") + "/rest/v1/" + path
    h = {"apikey": os.environ["SUPABASE_SECRET_KEY"], "Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        sys.exit(f"HTTP {e.code} on {method} /{path.split('?')[0]}: {e.read().decode()[:300]}")


def remote_count(extra=""):
    _, h, _ = call("GET", "minister_definitions?select=record_key" + extra, headers={"Prefer": "count=exact", "Range": "0-0"})
    return int(h["Content-Range"].split("/")[1])


def fetch_all(cols):
    out, start = [], 0
    while True:
        _, _, b = call("GET", f"minister_definitions?select={cols}&order=record_key",
                       headers={"Range-Unit": "items", "Range": f"{start}-{start + 999}"})
        page = json.loads(b)
        out += page
        if len(page) < 1000:
            return out
        start += 1000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--expect-empty", action="store_true")
    args = ap.parse_args()
    for v in ("SUPABASE_URL", "SUPABASE_SECRET_KEY"):
        if not os.environ.get(v):
            sys.exit(f"{v} is not set")
    recs = load_manifest()
    before = remote_count()
    print(f"manifest: {len(recs)} records; remote rows before: {before}")
    if args.expect_empty and before:
        sys.exit("table is not empty; aborting (--expect-empty)")
    if args.dry_run:
        print("dry run: nothing written")
        return
    for i in range(0, len(recs), BATCH):
        batch = [{c: r[c] for c in COLS} for r in recs[i:i + BATCH]]
        call("POST", "minister_definitions?on_conflict=record_key", batch,
             {"Prefer": "resolution=merge-duplicates,return=minimal"})
    rows = fetch_all("record_key,minister,definition_type,origin_status,content_hash,review_status,source_citation")
    ok = len(rows) == len(recs)
    print(f"remote rows: {len(rows)}  manifest records: {len(recs)}")
    for label, key in (("minister", "minister"), ("definition_type", "definition_type"), ("origin_status", "origin_status")):
        remote = dict(sorted(Counter(r[key] for r in rows).items()))
        match = remote == counts(recs, lambda r: r[key])
        ok &= match
        print(f"by {label}: {'OK' if match else 'MISMATCH'}  {remote}")
    rh = {r["record_key"]: r["content_hash"] for r in rows}
    bad = [r["record_key"] for r in recs if rh.get(r["record_key"]) != r["content_hash"]]
    print(f"content_hash mismatches: {len(bad)}")
    ok &= not bad
    print("review_status:", dict(Counter(r["review_status"] for r in rows)))
    print("rows with NULL source_citation:", sum(r["source_citation"] is None for r in rows),
          "(manifest:", sum(r["source_citation"] is None for r in recs), ")")
    print("VERIFIED" if ok else "VERIFICATION FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
