'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const preflight = require('../kavach-preflight-tool');

function decision(verdict = 'ALLOW', decidedBy = 'Speaker', overrides = {}) {
  const ministers = {
    VAULT: { minister: 'VAULT', verdict: 'ALLOW', reason: 'no rule matched', diagnostics: {} },
    EXECUTOR: { minister: 'EXECUTOR', verdict: 'ALLOW', reason: 'no rule matched', diagnostics: {} },
    CHANNEL: { minister: 'CHANNEL', verdict: 'ALLOW', reason: 'no rule matched', diagnostics: {} },
    NAVIGATOR: { minister: 'NAVIGATOR', verdict: 'ALLOW', reason: 'no rule matched', diagnostics: { policy_ids: [] } }
  };
  Object.assign(ministers, overrides);
  return { verdict, decided_by: decidedBy, reason: 'RAW_REASON_MUST_NOT_LEAK', ministers };
}

test('validates command input and caps its length', () => {
  assert.throws(() => preflight.validateInput({ command: '  ' }), /non-empty/);
  assert.throws(() => preflight.validateInput({ command: 'x'.repeat(12001) }), /length limit/);
  assert.equal(preflight.validateInput({ command: 'pwd', intent: '  inspect  ' }).intent, 'inspect');
});

test('restricts all preflight requests to loopback API endpoints', () => {
  assert.equal(preflight.localCheckUrl('http://127.0.0.1:8088/'), 'http://127.0.0.1:8088/check');
  assert.equal(preflight.localCheckUrl('http://localhost:8088'), 'http://localhost:8088/check');
  assert.throws(() => preflight.localCheckUrl('https://example.com'), /localhost\/loopback/);
  assert.throws(() => preflight.localCheckUrl('http://127.0.0.1:8088/proxy'), /localhost\/loopback/);
  assert.throws(() => preflight.localCheckUrl('http://user:pass@127.0.0.1:8088'), /localhost\/loopback/);
});

test('builds a synthetic API record and never runs the command', () => {
  const payload = preflight.buildPayload(
    { command: 'pwd && whoami', intent: 'Show location and account name' },
    'kavach-preflight-unit-test'
  );
  assert.equal(payload.tool_name, 'run_in_terminal');
  assert.equal(payload.arguments.command, 'pwd && whoami');
  assert.equal(payload.session_id, 'kavach-preflight-unit-test');
  assert.equal(payload.context.user_instruction, 'Show location and account name');
  assert.equal(Object.hasOwn(payload, 'execute'), false);
});

test('returns only normalized minister verdicts and rule IDs, never raw reasons', () => {
  const result = preflight.summarizeDecision(decision('BLOCK', 'EXECUTOR', {
    EXECUTOR: {
      minister: 'EXECUTOR', verdict: 'BLOCK',
      reason: 'SECRET_COMMAND_AND_ARGUMENT',
      matched_id: 'EXECUTOR-PREFILTER:os-system-call',
      diagnostics: {}
    },
    NAVIGATOR: {
      minister: 'NAVIGATOR', verdict: 'BLOCK',
      reason: 'INTERNAL_DETAIL',
      diagnostics: { policy_ids: ['POL-005', 'POL-007'] }
    }
  }));
  assert.equal(result.verdict, 'BLOCK');
  assert.equal(result.decided_by, 'EXECUTOR');
  assert.match(result.ministers.EXECUTOR.rule_ids.join(','), /os-system-call/);
  assert.match(result.agent_guidance, /Do not execute/);
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /SECRET_COMMAND_AND_ARGUMENT|INTERNAL_DETAIL|RAW_REASON_MUST_NOT_LEAK/);
  assert.match(serialized, /synthetic preflight/);
});

test('posts the exact command as JSON to loopback and validates the live API result', async () => {
  let seenUrl;
  let seenOptions;
  const result = await preflight.inspectCommand(
    { command: 'git status --short', intent: 'Inspect working tree' },
    {
      apiBaseUrl: 'http://127.0.0.1:8088',
      sessionId: 'kavach-test-session',
      fetchImpl: async (url, options) => {
        seenUrl = url;
        seenOptions = options;
        return { ok: true, status: 200, json: async () => decision() };
      }
    }
  );
  assert.equal(seenUrl, 'http://127.0.0.1:8088/check');
  assert.equal(seenOptions.method, 'POST');
  assert.equal(seenOptions.redirect, 'error');
  const payload = JSON.parse(seenOptions.body);
  assert.equal(payload.arguments.command, 'git status --short');
  assert.equal(payload.context.user_instruction, 'Inspect working tree');
  assert.equal(result.status, 'checked');
  assert.equal(result.verdict, 'ALLOW');
  assert.match(result.agent_guidance, /independent real PreToolUse hook/);
});

test('does not present API failure or malformed results as ALLOW', async () => {
  const unavailable = await preflight.inspectCommand(
    { command: 'pwd' },
    { apiBaseUrl: 'http://127.0.0.1:8088', fetchImpl: async () => { throw new Error('offline'); } }
  );
  assert.equal(unavailable.status, 'unavailable');
  assert.equal(unavailable.verdict, 'UNVERIFIED');
  assert.match(unavailable.agent_guidance, /Do not treat this as ALLOW/);

  const malformed = await preflight.inspectCommand(
    { command: 'pwd' },
    { apiBaseUrl: 'http://127.0.0.1:8088', fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ verdict: 'ALLOW' }) }) }
  );
  assert.equal(malformed.status, 'unavailable');
  assert.equal(malformed.verdict, 'UNVERIFIED');
});

test('refuses a remote URL before invoking fetch', async () => {
  let called = false;
  const result = await preflight.inspectCommand(
    { command: 'pwd' },
    { apiBaseUrl: 'https://example.com', fetchImpl: async () => { called = true; } }
  );
  assert.equal(called, false);
  assert.equal(result.verdict, 'UNVERIFIED');
});

test('manifest exposes a model tool with an explicit no-execution contract', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const tool = manifest.contributes.languageModelTools.find((item) => item.name === preflight.TOOL_NAME);
  assert.ok(tool);
  assert.match(tool.modelDescription, /never executes/i);
  assert.deepEqual(tool.inputSchema.required, ['command']);
  assert.equal(tool.inputSchema.additionalProperties, false);
});
