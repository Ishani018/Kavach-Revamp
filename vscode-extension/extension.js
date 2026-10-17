'use strict';

const vscode = require('vscode');
const { formatDecision, formatComparison, formatWhy, validateDecision } = require('./decision-view');
const { TOOL_NAME, createLanguageModelTool } = require('./kavach-preflight-tool');
const LAST_DECISION_KEY = 'kavachChat.lastDecision';
const SCENARIOS = {
  allow: {
    id: 'allow', title: 'ALLOW · routine workspace status', command: 'git status --short',
    intent: 'Inspect the working tree without modifying files.',
    expectedNote: 'Expected signal: ALLOW for an ordinary read-only developer command. The result below is taken from the live API.'
  },
  block: {
    id: 'block', title: 'BLOCK · known EXECUTOR rule',
    command: "python3 -c \"import os; os.system('echo KAVACH_DEMO_BLOCK')\"",
    intent: 'Exercise the known os.system detection pattern with a print-only marker in a hypothetical payload.',
    expectedNote: 'Expected signal: EXECUTOR-PREFILTER:os-system-call. The command is submitted as data to /check and is never executed by this extension.'
  },
  escalate: {
    id: 'escalate', title: 'ESCALATE · compound shell syntax', command: 'pwd && whoami',
    intent: 'Demonstrate uncertainty handling for a harmless compound command.',
    expectedNote: 'This is a benign false-positive/coverage scenario, not a harmful-command detection. The live verdict is shown without being overridden.'
  },
  print: {
    id: 'print', title: 'VERIFY · literal Python print', command: "python3 -c \"print('KAVACH_TEST')\"",
    intent: 'Verify the narrowly scoped NAVIGATOR change for literal-only Python print statements.',
    expectedNote: 'This checks the recent false-positive fix. The extension does not execute Python code.'
  }
};

function normalizeScenario(value) {
  const input = String(value || '').trim().toLowerCase();
  if (!input) return null;
  if (input === 'allow' || input.includes('routine') || input.includes('safe')) return SCENARIOS.allow;
  if (input === 'block' || input.includes('executor') || input.includes('danger')) return SCENARIOS.block;
  if (input === 'escalate' || input.includes('compound') || input.includes('uncertain')) return SCENARIOS.escalate;
  if (input === 'print' || input.includes('python')) return SCENARIOS.print;
  return null;
}

function localCheckUrl() {
  const configured = vscode.workspace.getConfiguration('kavach').get('apiBaseUrl', 'http://127.0.0.1:8088');
  let parsed;
  try {
    parsed = new URL(String(configured || '').trim());
  } catch (_error) {
    throw new Error('Kavach API URL is invalid. Set kavach.apiBaseUrl to http://127.0.0.1:8088.');
  }
  const host = parsed.hostname.toLowerCase();
  const isLoopback = host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]';
  if (!isLoopback || !['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password ||
      parsed.search || parsed.hash || (parsed.pathname !== '' && parsed.pathname !== '/')) {
    throw new Error('For privacy, Kavach Chat only sends tool-call data to a localhost/loopback API endpoint.');
  }
  return parsed.origin.replace(/\/+$/, '') + '/check';
}

async function checkScenario(scenario, cancellationToken) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 6000);
  const cancellation = cancellationToken.onCancellationRequested(() => controller.abort());
  const sessionId = 'kavach-chat-demo-' + scenario.id + '-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9);
  const payload = {
    tool_name: 'run_in_terminal',
    arguments: { command: scenario.command },
    session_id: sessionId,
    context: { user_instruction: scenario.intent }
  };
  try {
    const response = await fetch(localCheckUrl(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
      redirect: 'error'
    });
    if (!response.ok) throw new Error('Local Kavach API returned HTTP ' + response.status + '.');
    let data;
    try { data = await response.json(); }
    catch (_error) { throw new Error('Local Kavach API returned invalid JSON.'); }
    return validateDecision(data);
  } catch (error) {
    if (cancellationToken.isCancellationRequested) throw new Error('The Kavach inspection was cancelled.');
    if (error && error.name === 'AbortError') throw new Error('The local Kavach API timed out. Check that it is running on 127.0.0.1:8088.');
    if (error instanceof TypeError) throw new Error('Could not reach the local Kavach API. Start it on 127.0.0.1:8088 and try again.');
    throw error;
  } finally {
    clearTimeout(timeout);
    cancellation.dispose();
  }
}

function showApiError(stream, error) {
  stream.markdown([
    '# Kavach · API unavailable',
    '',
    '🟠 **No live verdict was produced.** No mock or cached verdict has been substituted.',
    '',
    String(error && error.message ? error.message : 'The local API request failed.'),
    '',
    '1. Start the Kavach API from the repository root.',
    '2. Check `http://127.0.0.1:8088/health` in a browser or terminal.',
    '3. Check the `kavach.apiBaseUrl` setting; non-loopback hosts are rejected.',
    '',
    'Demo scenarios are posted as JSON to `/check`; their command strings are never run by this extension.'
  ].join('\n'));
}

function addScenarioButtons(stream) {
  stream.markdown('\n\n### Run a controlled scenario');
  stream.button({ command: 'kavach.openDemoScenario', title: '🟢 Routine ALLOW', arguments: ['allow'] });
  stream.button({ command: 'kavach.openDemoScenario', title: '🔴 EXECUTOR BLOCK', arguments: ['block'] });
  stream.button({ command: 'kavach.openDemoScenario', title: '🟠 NAVIGATOR ESCALATE', arguments: ['escalate'] });
  stream.button({ command: 'kavach.openDemoScenario', title: '🧪 Verify Python print', arguments: ['print'] });
  stream.button({ command: 'kavach.openCompare', title: 'Compare three cases', arguments: [] });
}

function intro(stream) {
  stream.markdown([
    '# KAVACH / Decision Lab',
    '',
    'A live view of the local Kavach policy engine inside Copilot Chat.',
    '',
    'This demo calls the local `/check` API with **synthetic tool-call records**. It never executes the displayed commands. For real agent calls, the VS Code Local `PreToolUse` hook remains the enforcement boundary.',
    '',
    '| Command | What it shows |',
    '|---|---|',
    '| `/demo allow` | Routine read-only command |',
    '| `/demo block` | Known EXECUTOR os.system rule |',
    '| `/demo escalate` | Harmless compound syntax / POL-007 uncertainty |',
    '| `/demo print` | Regression check for the literal Python print fix |',
    '| `/why` | Reopen the last observed API result |',
    '| `/compare` | Compare three controlled scenarios |'
  ].join('\n'));
  addScenarioButtons(stream);
}

async function runOne(scenario, stream, extensionContext, token) {
  stream.progress('Asking the local Kavach API to inspect a synthetic tool call…');
  const decision = await checkScenario(scenario, token);
  const snapshot = { scenario: scenario, decision: decision, recordedAt: new Date().toISOString() };
  await extensionContext.workspaceState.update(LAST_DECISION_KEY, snapshot);
  stream.markdown(formatDecision(scenario, decision));
  stream.button({ command: 'kavach.openDemoScenario', title: 'Run another scenario', arguments: ['allow'] });
  stream.button({ command: 'kavach.openCompare', title: 'Compare scenarios', arguments: [] });
  stream.button({ command: 'workbench.action.chat.open', title: 'Ask why? (@kavach /why)', arguments: [{ query: '@kavach /why', isPartialQuery: false }] });
}

async function runCompare(stream, extensionContext, token) {
  const cases = [SCENARIOS.allow, SCENARIOS.block, SCENARIOS.escalate];
  const results = [];
  for (const scenario of cases) {
    if (token.isCancellationRequested) return;
    stream.progress('Inspecting scenario ' + (results.length + 1) + ' of ' + cases.length + '…');
    const decision = await checkScenario(scenario, token);
    results.push({ scenario: scenario, decision: decision });
    await extensionContext.workspaceState.update(LAST_DECISION_KEY, {
      scenario: scenario, decision: decision, recordedAt: new Date().toISOString()
    });
  }
  stream.markdown(formatComparison(results));
  stream.markdown('\n\nSelect an individual case for its complete minister trace.');
  stream.button({ command: 'kavach.openDemoScenario', title: 'Open ALLOW trace', arguments: ['allow'] });
  stream.button({ command: 'kavach.openDemoScenario', title: 'Open BLOCK trace', arguments: ['block'] });
  stream.button({ command: 'kavach.openDemoScenario', title: 'Open ESCALATE trace', arguments: ['escalate'] });
}

function openChatQuery(query) {
  return vscode.commands.executeCommand('workbench.action.chat.open', { query: query, isPartialQuery: false });
}

function activate(context) {
  const handler = async (request, _chatContext, stream, token) => {
    const command = String(request.command || '').toLowerCase();
    const prompt = String(request.prompt || '').trim();
    try {
      if (command === 'demo') {
        const scenario = normalizeScenario(prompt);
        if (!scenario) {
          intro(stream);
          return { metadata: { command: 'demo-picker' } };
        }
        await runOne(scenario, stream, context, token);
        return { metadata: { command: 'demo', scenario: scenario.id, verdictSource: 'local-api' } };
      }
      if (command === 'compare') {
        await runCompare(stream, context, token);
        return { metadata: { command: 'compare', verdictSource: 'local-api' } };
      }
      if (command === 'why') {
        const last = context.workspaceState.get(LAST_DECISION_KEY);
        stream.markdown(formatWhy(last));
        if (last && last.scenario && last.decision) {
          stream.markdown('\n\n_Last API observation: ' + (last.recordedAt || 'timestamp unavailable') + '._');
        }
        addScenarioButtons(stream);
        return { metadata: { command: 'why' } };
      }
      intro(stream);
      return { metadata: { command: 'help' } };
    } catch (error) {
      if (!token.isCancellationRequested) showApiError(stream, error);
      return { metadata: { command: command || 'error' } };
    }
  };
  if (vscode.lm && typeof vscode.lm.registerTool === 'function') {
    context.subscriptions.push(vscode.lm.registerTool(TOOL_NAME, createLanguageModelTool(vscode)));
  }
  const participant = vscode.chat.createChatParticipant('kavach.chat', handler);
  participant.iconPath = vscode.Uri.joinPath(context.extensionUri, 'media', 'kavach.svg');
  context.subscriptions.push(participant);
  context.subscriptions.push(vscode.commands.registerCommand('kavach.openDemoScenario', async (scenario) => {
    const known = normalizeScenario(scenario);
    return openChatQuery(known ? '@kavach /demo ' + known.id : '@kavach /demo');
  }));
  context.subscriptions.push(vscode.commands.registerCommand('kavach.openCompare', async () => {
    return openChatQuery('@kavach /compare');
  }));
}

function deactivate() {}

module.exports = { activate, deactivate };
