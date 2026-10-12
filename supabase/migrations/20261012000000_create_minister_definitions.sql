-- minister_definitions: catalogue of Kavach minister definitions (VAULT, EXECUTOR,
-- CHANNEL, NAVIGATOR) imported from the Git repository. Git remains the source of
-- truth; this table is a queryable copy that preserves each original definition.
-- Nothing reads this table at runtime yet.

create table public.minister_definitions (
  id                uuid        primary key default gen_random_uuid(),

  -- Stable key so repeated imports upsert instead of duplicating:
  -- "<MINISTER>|<definition_type>|<definition_id>|<git_ref>:<repo_path>"
  record_key        text        not null unique,

  minister          text        not null
    check (minister in ('VAULT', 'EXECUTOR', 'CHANNEL', 'NAVIGATOR')),
  definition_type   text        not null
    check (definition_type in (
      'corpus_pattern', 'deterministic_rule', 'parser_pattern',
      'channel_source_tool', 'channel_destination_tool', 'channel_source_rule', 'channel_behavior',
      'minister_description', 'threshold_config',
      'navigator_authflow_taxonomy', 'navigator_tier_rule')),
  definition_id     text,

  l1_intent         text,
  l2_mechanism      text,
  l3_surface        text,
  category          text,

  -- Provenance. NULL means unknown; never filled in by guesswork.
  source_citation   text,
  technique_ids     text[]      not null default '{}',
  source_url        text,
  source_license    text,
  provenance_flags  text[]      not null default '{}',

  -- The original structured definition, verbatim, plus file-level context.
  definition        jsonb       not null,
  context           jsonb       not null default '{}'::jsonb,

  repo_path         text        not null,
  git_ref           text        not null,
  source_commit_sha text
    check (source_commit_sha is null or source_commit_sha ~ '^[0-9a-f]{40}$'),
  content_hash      text        not null
    check (content_hash ~ '^[0-9a-f]{64}$'),

  -- Where the definition lives. This is NOT a statement that it is correct.
  origin_status     text        not null
    check (origin_status in (
      'current_mvp', 'legacy_main', 'candidate', 'experimental', 'historical', 'unknown')),
  -- Independent of origin. Imports never set anything but the default.
  review_status     text        not null default 'unreviewed'
    check (review_status in (
      'unreviewed', 'in_review', 'source_verified', 'validated', 'approved', 'rejected')),

  notes             text,
  imported_at       timestamptz not null default now(),
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);

comment on table public.minister_definitions is
  'Catalogue of Kavach minister definitions imported from Git. origin_status = where it lives; review_status = whether anyone has verified it.';

create index minister_definitions_minister_type_idx on public.minister_definitions (minister, definition_type);
create index minister_definitions_origin_idx        on public.minister_definitions (origin_status);
create index minister_definitions_review_idx        on public.minister_definitions (review_status);
create index minister_definitions_definition_id_idx on public.minister_definitions (definition_id);
create index minister_definitions_content_hash_idx  on public.minister_definitions (content_hash);
create index minister_definitions_technique_ids_idx on public.minister_definitions using gin (technique_ids);
create index minister_definitions_definition_gin    on public.minister_definitions using gin (definition jsonb_path_ops);

create or replace function public.minister_definitions_touch_updated_at()
returns trigger language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger minister_definitions_touch_updated_at
  before update on public.minister_definitions
  for each row execute function public.minister_definitions_touch_updated_at();

-- Access control: RLS on, deliberately NO policies. anon/authenticated get nothing;
-- the service role / table owner (trusted server-side import) bypasses RLS.
alter table public.minister_definitions enable row level security;
alter table public.minister_definitions force row level security;
revoke all on public.minister_definitions from anon, authenticated;
