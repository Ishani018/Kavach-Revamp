'use strict';

const MINISTERS = ['VAULT', 'EXECUTOR', 'CHANNEL', 'NAVIGATOR'];
const VERDICTS = new Set(['ALLOW', 'BLOCK', 'ESCALATE']);
const ICONS = { ALLOW: '🟢', BLOCK: '🔴', ESCALATE: '🟠' };
const POLICY_TITLES = {
  'POL-001': 'proven-exfil-to-unauthorized-destination',
  'POL-002': 'contract-scope-violation',
  'POL-003': 'untrusted-content-privilege-induction',
  'POL-004': 'decode-execute-structural',
  'POL-005': 'specialist-hard-block-preserved',
  'POL-006': 'high-impact-without-approval',
  'POL-007': 'insufficient-evidence-coverage',
  'POL-008': 'explicit-task-restriction-violation',
  'POL-009': 'prior-sensitive-artifact-to-unauthorized-destination'
};

function validateDecision(value) {
  if (!value || typeof value !== 'object' || !VERDICTS.has(value.verdict)) {
    throw new Error('Kavach returned no valid overall verdict.');
  }
  if (typeof value.decided_by !== 'string' || !value.decided_by) {
    throw new Error('Kavach returned no deciding authority.');
  }
  if (!value.ministers || typeof value.ministers !== 'object') {
    throw new Error('Kavach returned no minister breakdown.');
  }
  for (const name of MINISTERS) {
    const minister = value.ministers[name];
    if (!minister || !VERDICTS.has(minister.verdict)) {
      throw new Error('Kavach returned an incomplete minister breakdown.');
    }
  }
  const expected = MINISTERS.some((name) => value.ministers[name].verdict === 'BLOCK')
    ? 'BLOCK'
    : MINISTERS.some((name) => value.ministers[name].verdict === 'ESCALATE')
      ? 'ESCALATE'
      : 'ALLOW';
  if (expected !== value.verdict) {
    throw new Error('Kavach returned inconsistent minister and overall verdicts.');
  }
  return value;
}

function ruleIds(minister) {
  const ids = [];
  if (typeof minister.matched_id === 'string' && minister.matched_id.trim()) {
    ids.push(minister.matched_id.trim());
  }
  const diagnosticIds = minister.diagnostics && minister.diagnostics.policy_ids;
  if (Array.isArray(diagnosticIds)) {
    for (const id of diagnosticIds) {
      if (typeof id === 'string' && id.trim() && !ids.includes(id.trim())) {
        ids.push(id.trim());
      }
    }
  }
  return ids.slice(0, 6);
}

function prettyRule(id) {
  return POLICY_TITLES[id] ? id + ' — ' + POLICY_TITLES[id] : id;
}

function ministerExplanation(name, minister) {
  const ids = ruleIds(minister);
  if (minister.verdict === 'ALLOW') {
    return ids.length ? 'No block was produced; evidence details are intentionally summarized.' : 'No blocking rule was reported.';
  }
  if (name === 'EXECUTOR' && minister.verdict === 'BLOCK') {
    return 'A dangerous-execution rule matched. Raw command text is deliberately withheld.';
  }
  if (name === 'VAULT') {
    return 'The credential/secret review returned ' + minister.verdict + '; sensitive values are withheld.';
  }
  if (name === 'CHANNEL') {
    return 'The data-movement/provenance review returned ' + minister.verdict + '; raw values are withheld.';
  }
  if (name === 'NAVIGATOR' && ids.length) {
    const evidence = 'Policy evidence: ' + ids.map(prettyRule).join('; ') + '.';
    return minister.verdict === 'ESCALATE'
      ? evidence + ' Coverage is unresolved; this is not by itself proof of malicious intent.'
      : evidence;
  }
  return minister.verdict === 'ESCALATE'
    ? 'Coverage or policy evidence is unresolved; this is not by itself proof of malicious intent.'
    : 'A policy or specialist rule denied the proposed action.';
}

function formatDecision(scenario, input) {
  const decision = validateDecision(input);
  const status = ICONS[decision.verdict] + ' **' + decision.verdict + '**';
  const rows = MINISTERS.map((name) => {
    const minister = decision.ministers[name];
    const ids = ruleIds(minister);
    const evidence = ids.length ? ids.map(prettyRule).join('; ') : 'No specific rule ID reported';
    return '| ' + name + ' | **' + minister.verdict + '** | ' + evidence + ' | ' + ministerExplanation(name, minister) + ' |';
  });
  return [
    '# ' + status + ' · ' + decision.decided_by,
    '',
    '> LIVE API RESULT · SYNTHETIC PRE-FLIGHT INSPECTION',
    '',
    '**Scenario:** ' + scenario.title,
    '**Proposed tool:** `run_in_terminal`',
    '**Intent:** ' + scenario.intent,
    '',
    '| Minister | Verdict | Rule / policy | Explanation |',
    '|---|---|---|---|',
    ...rows,
    '',
    '### Decision path',
    '`Proposed call` → `VAULT` → `EXECUTOR` → `CHANNEL` → `NAVIGATOR` → `Speaker`',
    '',
    '**What happened:** Kavach evaluated a synthetic tool-call record through the local `/check` API. **This chat demo did not execute the scenario command and does not prove the VS Code pre-tool hook enforced it.**',
    '',
    scenario.expectedNote ? '**Demo note:** ' + scenario.expectedNote : '',
    '',
    'Use `/why` for the last API result, or `/compare` to run all three controlled cases.'
  ].filter(Boolean).join('\n').replaceAll('`', String.fromCharCode(96));
}

function formatComparison(results) {
  const rows = results.map((item) => {
    const decision = validateDecision(item.decision);
    const decisive = MINISTERS
      .filter((name) => decision.ministers[name].verdict !== 'ALLOW')
      .map((name) => {
        const ids = ruleIds(decision.ministers[name]);
        return name + (ids.length ? ' (' + ids.join(', ') + ')' : '');
      });
    return '| ' + item.scenario.title + ' | **' + decision.verdict + '** | ' + decision.decided_by + ' | ' + (decisive.join('; ') || 'No blocking/escalation minister') + ' |';
  });
  return [
    '# Kavach · Scenario comparison',
    '',
    '> LIVE API RESULTS · SYNTHETIC CALLS · NO SCENARIO COMMAND WAS EXECUTED',
    '',
    '| Scenario | Verdict | Decider | Blocking / escalation signals |',
    '|---|---|---|---|',
    ...rows,
    '',
    '### Pipeline',
    '`Synthetic call` → `4 ministers` → `Speaker` → `Local API response`',
    '',
    'These are controlled demonstrations of current rules, not a benchmark or proof of broad detection coverage.'
  ].join('\n').replaceAll('`', String.fromCharCode(96));
}

function formatWhy(snapshot) {
  if (!snapshot || !snapshot.scenario || !snapshot.decision) {
    return 'No Kavach Chat decision is stored yet. Run `/demo allow`, `/demo block`, `/demo escalate`, or `/demo print` first.'.replaceAll('`', String.fromCharCode(96));
  }
  return formatDecision(snapshot.scenario, snapshot.decision);
}

module.exports = { MINISTERS, validateDecision, ruleIds, formatDecision, formatComparison, formatWhy };
