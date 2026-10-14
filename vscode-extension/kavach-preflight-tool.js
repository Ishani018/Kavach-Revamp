'use strict';

const { MINISTERS, validateDecision, ruleIds } = require('./decision-view');

const TOOL_NAME = 'kavach-chat-participant_inspect_terminal_command';
const MAX_COMMAND_CHARS = 12000;
const MAX_INTENT_CHARS = 1500;

const MINISTER_ROLES = {
  VAULT: 'Reviews credential and secret exposure.',
  EXECUTOR: 'Reviews dangerous execution and code-launch patterns.',
  CHANNEL: 'Reviews sensitive-data movement and destination provenance.',
  NAVIGATOR: 'Reviews task-contract alignment, evidence coverage, and trajectory policies.'
};

const POLICY_EXPLANATIONS = {
  'POL-001': 'Sensitive data is proposed for a destination outside the task contract.',
  'POL-002': 'A path falls outside the declared workspace scope.',
  'POL-003': 'Untrusted content attempted to change what the task contract authorizes.',
  'POL-004': 'A decode-then-execute structure was confirmed; the policy escalates unless stronger evidence supports a block.',
  'POL-005': 'A specialist minister returned a hard block and NAVIGATOR preserved it.',
  'POL-006': 'A contract-flagged high-impact action lacks a recorded approval event.',
  'POL-007': 'Evidence coverage is incomplete. This is uncertainty, not by itself proof of malicious intent.',
  'POL-008': 'The requested tool category is explicitly denied by the task contract.',
  'POL-009': 'The session previously touched sensitive data and now proposes sending it to an unapproved destination.'
};

function explainRuleId(id) {
  if (POLICY_EXPLANATIONS[id]) return POLICY_EXPLANATIONS[id];
  if (id === 'EXECUTOR-PREFILTER:os-system-call') {
    return 'EXECUTOR detected a known programmatic shell-execution pattern.';
  }
  if (id.startsWith('EXECUTOR-')) {
    return 'EXECUTOR reported a detector-specific execution signal; consult the matching rule documentation.';
  }
  return 'The minister reported this rule ID; its meaning has not been expanded by the preflight formatter.';
}

function validateInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('Input must be an object with a command string.');
  }
  if (typeof input.command !== 'string' || !input.command.trim()) {
    throw new Error('A non-empty command string is required.');
  }
  if (input.command.length > MAX_COMMAND_CHARS) {
    throw new Error('The command exceeds the preflight length limit.');
  }
  if (input.intent !== undefined && typeof input.intent !== 'string') {
    throw new Error('Intent must be a string when supplied.');
  }
  return {
    command: input.command,
    intent: typeof input.intent === 'string' && input.intent.trim()
      ? input.intent.trim().slice(0, MAX_INTENT_CHARS)
      : 'Inspect this proposed terminal command before execution.'
  };
}

function localCheckUrl(configured) {
  let parsed;
  try {
    parsed = new URL(String(configured || 'http://127.0.0.1:8088').trim());
  } catch (_error) {
    throw new Error('Kavach API URL is invalid. Use a localhost/loopback URL.');
  }
  const host = parsed.hostname.toLowerCase();
  const isLoopback = host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]';
  if (!isLoopback || !['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password ||
      parsed.search || parsed.hash || (parsed.pathname !== '' && parsed.pathname !== '/')) {
    throw new Error('For privacy, preflight only sends command data to a localhost/loopback Kavach API.');
  }
  return parsed.origin.replace(/\/+$/, '') + '/check';
}

function buildPayload(input, sessionId) {
  const safe = validateInput(input);
  if (typeof sessionId !== 'string' || !sessionId.trim()) {
    throw new Error('A synthetic preflight session ID is required.');
  }
  return {
    tool_name: 'run_in_terminal',
    arguments: { command: safe.command },
    session_id: sessionId,
    context: { user_instruction: safe.intent }
  };
}

function summarizeDecision(value) {
  const decision = validateDecision(value);
  const ministers = {};
  for (const name of MINISTERS) {
    const result = decision.ministers[name];
    const ids = ruleIds(result);
    ministers[name] = {
      role: MINISTER_ROLES[name],
      verdict: result.verdict,
      rule_ids: ids,
      rule_explanations: ids.map((id) => ({ id, meaning: explainRuleId(id) }))
    };
  }

  let agentGuidance;
  if (decision.verdict === 'BLOCK') {
    agentGuidance = 'STOP. Do not execute this command, retry it, or switch to another tool/path to achieve the same effect. Explain the blocking result to the user.';
  } else if (decision.verdict === 'ESCALATE') {
    agentGuidance = 'STOP before execution. Escalation means policy/evidence is unresolved, not necessarily that the command is malicious. Explain the uncertainty and ask the user how to proceed; do not route around this result.';
  } else {
    agentGuidance = 'Kavach returned ALLOW for this synthetic preflight only. The intent supplied to preflight is not independently authenticated and cannot establish user authorization. This is not proof of safety or permission to skip the independent real PreToolUse hook; submit the actual unchanged call through the normal guarded workflow.';
  }

  return {
    status: 'checked',
    source: 'local Kavach /check API',
    evaluation_type: 'synthetic preflight; intent is caller-supplied and unauthenticated; command text is sent as JSON and never executed',
    verdict: decision.verdict,
    decided_by: decision.decided_by,
    ministers,
    agent_guidance: agentGuidance
  };
}

function unavailableResult(error) {
  return {
    status: 'unavailable',
    source: 'local Kavach /check API',
    verdict: 'UNVERIFIED',
    error: String(error && error.message ? error.message : 'The local preflight request failed.').slice(0, 240),
    agent_guidance: 'No valid preflight verdict was produced. Do not treat this as ALLOW or execute based on this result. Tell the user that preflight was unavailable; the independent real PreToolUse hook remains authoritative.'
  };
}

async function inspectCommand(input, options = {}) {
  const safe = validateInput(input);
  let url;
  try {
    url = localCheckUrl(options.apiBaseUrl);
  } catch (error) {
    return unavailableResult(error);
  }
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    return unavailableResult(new Error('This VS Code runtime does not provide fetch.'));
  }

  const controller = new AbortController();
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 5000;
  const timer = setTimeout(() => controller.abort(), Math.min(Math.max(timeoutMs, 100), 8000));
  let cancellation;
  if (options.token && typeof options.token.onCancellationRequested === 'function') {
    cancellation = options.token.onCancellationRequested(() => controller.abort());
  }

  try {
    const sessionId = options.sessionId || ('kavach-preflight-' + require('crypto').randomUUID());
    const payload = buildPayload(safe, sessionId);
    const response = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
      redirect: 'error'
    });
    if (!response || !response.ok) {
      throw new Error('Local Kavach API returned HTTP ' + (response && response.status ? response.status : 'unknown') + '.');
    }
    let data;
    try {
      data = await response.json();
    } catch (_error) {
      throw new Error('Local Kavach API returned invalid JSON.');
    }
    return summarizeDecision(data);
  } catch (error) {
    return unavailableResult(error);
  } finally {
    clearTimeout(timer);
    if (cancellation && typeof cancellation.dispose === 'function') cancellation.dispose();
  }
}

function createLanguageModelTool(vscode) {
  return {
    async prepareInvocation(options) {
      const safe = validateInput(options.input);
      const message = new vscode.MarkdownString();
      message.appendMarkdown('Send this proposed command as data to the local Kavach policy API for inspection. **This tool will not execute it.**');
      message.appendMarkdown('\n\nProposed command:');
      message.appendCodeblock(safe.command, 'sh');
      message.appendMarkdown('The normal Local PreToolUse hook independently checks the real tool call.');
      return {
        invocationMessage: 'Inspecting proposed terminal command with local Kavach',
        confirmationMessages: {
          title: 'Kavach terminal preflight',
          message
        }
      };
    },

    async invoke(options, token) {
      const apiBaseUrl = vscode.workspace.getConfiguration('kavach').get('apiBaseUrl', 'http://127.0.0.1:8088');
      const result = await inspectCommand(options.input, { apiBaseUrl, token });
      return new vscode.LanguageModelToolResult([
        new vscode.LanguageModelTextPart(JSON.stringify(result, null, 2))
      ]);
    }
  };
}

module.exports = {
  TOOL_NAME,
  validateInput,
  localCheckUrl,
  buildPayload,
  summarizeDecision,
  unavailableResult,
  inspectCommand,
  createLanguageModelTool,
  explainRuleId,
  POLICY_EXPLANATIONS,
  MINISTER_ROLES
};
