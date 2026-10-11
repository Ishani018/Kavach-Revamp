# Scope

Kavach has three moving parts:

1. **Ministers** inspect one proposed tool action and return a vote.
2. **Speaker** combines those votes using simple, explicit rules.
3. **Monitor** wires the ministers and Speaker together.

## Votes

A minister returns one of:

- `ALLOW` — this minister's checks passed.
- `BLOCK` — this minister found a policy violation.
- `REVIEW` — this minister wants the action paused for review.
- `ABSTAIN` — this minister did not make a decision, for example because it is not implemented or lacks evidence.

The Speaker returns:

- `BLOCK` if any minister votes BLOCK.
- `REVIEW` if no minister blocks and at least one votes REVIEW.
- `INDETERMINATE` if no minister blocks/reviews and at least one abstains.
- `ALLOW` only when every minister explicitly votes ALLOW.

That last rule matters: an unimplemented or unavailable minister must not silently turn into permission.

## Keep it simple

- One minister per file, one responsibility per minister.
- Ministers do not call each other.
- Ministers do not decide the final verdict.
- Only the Speaker combines votes.
- No framework-specific code in the core.
- A minister is not considered implemented until it has malicious and benign tests.
