# Attribution and licence notices (Phase A candidate data)

This folder reproduces short excerpts from three public sources, selected and lightly transformed. Sources, pinned
versions and licences are recorded per item and in `phase_a_manifest.json`. This is attribution, not legal advice.

## RedCode (RedCode-Exec, bash)
- Source: https://github.com/AI-secure/RedCode, commit `c84b6db88fd8bd258e29f12e692ccfd4287a454d`
- Licence: MIT, Copyright (c) 2024 RedCode Authors (https://github.com/AI-secure/RedCode/blob/c84b6db88fd8bd258e29f12e692ccfd4287a454d/LICENSE)
- Used: the records of `dataset/RedCode-Exec/bash2text_dataset_json/*.json`, unchanged in each item's `original` field.
- These are test inputs describing risky behaviour. They must never be run outside an isolated test environment.

## tldr-pages
- Source: https://github.com/tldr-pages/tldr, commit `3b04259a58d0bfecaa31c3179b3d349a81ef7893`
- Copyright (c) 2014-present the tldr-pages team and contributors.
- Licence: Creative Commons Attribution 4.0 International (https://creativecommons.org/licenses/by/4.0/); see
  https://github.com/tldr-pages/tldr/blob/3b04259a58d0bfecaa31c3179b3d349a81ef7893/LICENSE.md
- Changes: in the derived `command` field only, each `{{placeholder}}` is replaced by the text inside it. The `original`
  field is unchanged.

## nebius/SWE-agent-trajectories
- Source: https://huggingface.co/datasets/nebius/SWE-agent-trajectories, revision `68195a1450865274106246d0d0296a1d6807b88e`
- Licence: CC BY 4.0 (`license: cc-by-4.0` in the dataset card).
- Used: the command in the last fenced block of selected agent turns from a fixed sample of 100 trajectories, unchanged in
  `original.command`; the full turn text is not copied (its SHA-256 is recorded).
- Changes: none to the command beyond trimming surrounding whitespace.
