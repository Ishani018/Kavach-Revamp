# Attribution and licence notices

This folder reproduces short command examples from two public projects, selected and lightly transformed for human review. The sources, versions and licences are recorded per row in `review_sheet.csv` and in `batch_manifest.json`.

## MITRE Caldera stockpile plugin

- Source: https://github.com/mitre/stockpile, commit `996ec41cd1c5d1c7cc09e620fc55dabe5aefd9cc`
- Licence: Apache License 2.0 (https://github.com/mitre/stockpile/blob/996ec41cd1c5d1c7cc09e620fc55dabe5aefd9cc/LICENSE)
- Material used: ability commands and their metadata (name, description, tactic, ATT&CK technique), unchanged in `original_command` and the `ctx_*` columns.
- Changes: for the transformed call, whitespace at the ends of the command was trimmed and the command was wrapped in a tool-call structure. Nothing else was modified.
- CALDERA is a trademark of The MITRE Corporation; this folder is not affiliated with or endorsed by MITRE.

## tldr-pages

- Source: https://github.com/tldr-pages/tldr, commit `3b04259a58d0bfecaa31c3179b3d349a81ef7893`
- Copyright (c) 2014-present the tldr-pages team and contributors.
- Licence: Creative Commons Attribution 4.0 International (https://creativecommons.org/licenses/by/4.0/); see https://github.com/tldr-pages/tldr/blob/3b04259a58d0bfecaa31c3179b3d349a81ef7893/LICENSE.md
- Material used: single-line example commands and the example description line from the page.
- Changes: in the transformed call only, each `{{placeholder}}` was replaced by the text inside it and the command was wrapped in a tool-call structure. `original_command` is unchanged.

This is attribution, not legal advice. Check the licences before redistributing the material outside this repository.
