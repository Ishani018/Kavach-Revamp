'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const view = require('../decision-view');

function decision(verdict, decidedBy, overrides) {
  const ministers = {
    VAULT: { minister: 'VAULT', verdict: 'ALLOW', reason: 'no rule matched', diagnostics: {} },
    EXECUTOR: { minister: 'EXECUTOR', verdict: 'ALLOW', reason: 'no rule matched', diagnostics: {} },
    CHANNEL: { minister: 'CHANNEL', verdict: 'ALLOW', reason: 'no rule matched', diagnostics: {} },
    NAVIGATOR: { minister: 'NAVIGATOR', verdict: 'ALLOW', reason: 'no blocking or escalation policy was returned', diagnostics: { policy_ids: [] } }
  };
  Object.assign(ministers, overrides || {});
  return { verdict, decided_by: decidedBy, reason: 'Never displayed verbatim', session_id: 'test', ministers };
}

test('validates a complete ALLOW response', () => {
  assert.equal(view.validateDecision(decision('ALLOW', 'Speaker')).verdict, 'ALLOW');
});

test('rejects a disagreement between minister results and overall verdict', () => {
  const value = decision('ALLOW', 'Speaker', {
    EXECUTOR: { minister: 'EXECUTOR', verdict: 'BLOCK', diagnostics: { policy_ids: [] } }
  });
  assert.throws(() => view.validateDecision(value), /inconsistent/);
});

test('renders exact EXECUTOR rule IDs without revealing raw reasons', () => {
  const value = decision('BLOCK', 'EXECUTOR', {
    EXECUTOR: {
      minister: 'EXECUTOR', verdict: 'BLOCK',
      reason: 'RAW SECRET OR COMMAND SHOULD NEVER BE SHOWN',
      matched_id: 'EXECUTOR-PREFILTER:os-system-call',
      diagnostics: {}
    },
    NAVIGATOR: {
      minister: 'NAVIGATOR', verdict: 'BLOCK',
      reason: 'internal details', matched_id: 'POL-005',
      diagnostics: { policy_ids: ['POL-005', 'POL-007'] }
    }
  });
  const rendered = view.formatDecision({ title: 'Known execution rule', intent: 'Exercise a known rule.' }, value);
  assert.match(rendered, /EXECUTOR-PREFILTER:os-system-call/);
  assert.match(rendered, /POL-007/);
  assert.match(rendered, /\n\n\| Minister \| Verdict/);
  assert.match(rendered, /did not execute the scenario command/);
  assert.doesNotMatch(rendered, /RAW SECRET OR COMMAND SHOULD NEVER BE SHOWN/);
});

test('formats an escalation as uncertainty rather than asserting malicious intent', () => {
  const value = decision('ESCALATE', 'NAVIGATOR', {
    NAVIGATOR: { minister: 'NAVIGATOR', verdict: 'ESCALATE', matched_id: 'POL-007', diagnostics: { policy_ids: ['POL-007'] } }
  });
  const rendered = view.formatDecision({ title: 'Compound command', intent: 'Demonstrate uncertainty.' }, value);
  assert.match(rendered, /POL-007/);
  assert.match(rendered, /not by itself proof of malicious intent/);
});

test('comparison reports live-result data and is explicitly not a benchmark', () => {
  const results = [
    { scenario: { title: 'Routine status' }, decision: decision('ALLOW', 'Speaker') },
    { scenario: { title: 'Execution rule' }, decision: decision('BLOCK', 'EXECUTOR', {
      EXECUTOR: { minister: 'EXECUTOR', verdict: 'BLOCK', matched_id: 'EXECUTOR-PREFILTER:os-system-call', diagnostics: {} }
    }) }
  ];
  const rendered = view.formatComparison(results);
  assert.match(rendered, /Routine status/);
  assert.match(rendered, /EXECUTOR-PREFILTER:os-system-call/);
  assert.match(rendered, /not a benchmark/);
});

test('handles absent previous result without fabricating one', () => {
  assert.match(view.formatWhy(undefined), /No Kavach Chat decision is stored yet/);
});
