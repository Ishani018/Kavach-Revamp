# minister_definitions import

Catalogue of VAULT / EXECUTOR / CHANNEL / NAVIGATOR definitions copied out of Git into Supabase.
Git stays the source of truth. Nothing at runtime reads this table.

Files
- `supabase/migrations/20261012000000_create_minister_definitions.sql` – table, constraints, indexes, RLS (no policies).
- `build_manifest.py` – reads pinned Git refs (`main`, `mvp-core`, `origin/navigator-rearch`) and writes `supabase/seed/manifest.jsonl` + `manifest_report.json`. Deterministic for the same commits.
- `import_definitions.py` – idempotent upsert keyed on `record_key`, then verifies remote counts and content hashes against the manifest. Never overwrites `review_status`.

Rebuild the manifest: `python supabase/import/build_manifest.py`

Apply to the remote project (one-time setup, not done yet)
1. `supabase init` (creates config.toml; keeps existing migrations), `supabase login`, `supabase link --project-ref fztysjqnvxudhcvxfopd` (the project named "kavach"; confirm that is the intended one).
2. `supabase db push --dry-run`, review, then `supabase db push`.
3. Export the database connection string (Dashboard > Project Settings > Database) in your shell only:
   `export SUPABASE_DB_URL='postgresql://...'`
4. `pip install -r supabase/import/requirements.txt`
5. `python supabase/import/import_definitions.py --dry-run`, then `python supabase/import/import_definitions.py --expect-empty`.

Never run `supabase db reset` against the linked project.
