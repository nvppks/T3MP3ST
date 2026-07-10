// =============================================================================
// LOCAL AGENT CONNECTORS — "bring your own already-authed agent"
// =============================================================================
// Detect + connect agent CLIs that already live, authenticated, on the operator's machine
// (Claude Code, Codex, Hermes) and drive them headlessly as t3mp3st operators.
//
// SECURITY POSTURE (important):
//   - We NEVER read, print, log, or transmit credential contents. Auth is detected purely by the
//     PRESENCE of the CLI's own auth artifact (a file path or a macOS keychain item) — never its bytes.
//   - We do NOT enter or store any key. The CLIs are already logged in by the user; we only invoke them.
//   - A "ping"/"dispatch" spawns the user's own CLI as a child process with a prompt and captures its
//     stdout (the model's reply to OUR prompt — not secrets). Everything is local + user-initiated.
// =============================================================================

import { execFile, execFileSync, spawn } from 'child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { homedir, tmpdir, userInfo } from 'os';
import { join } from 'path';

// t3mp3st injects its OWN provider keys (from .env) into the server process. If we let those leak into
// a spawned CLI, the CLI uses t3mp3st's key instead of the user's native login → 401. The entire point
// of this feature is "use the agent you already authed", so we strip these before spawning so each CLI
// falls back to its own auth (keychain / ~/.codex/auth.json / ~/.hermes/.env).
const PROVIDER_ENV_TO_STRIP = [
  'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_MODEL',
  'OPENAI_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_API_BASE', 'OPENAI_ORGANIZATION',
  'OPENROUTER_API_KEY',
];

/**
 * The REAL user home where the agent CLIs keep their own auth artifacts
 * (~/.claude.json, ~/.codex/auth.json, ~/.hermes/.env, macOS keychain).
 *
 * DELIBERATELY separate from os.homedir()/$HOME: T3MP3ST may run with HOME redirected
 * (e.g. an isolated app-config dir), and os.homedir() returns that redirected path. Detecting
 * OR spawning the user's CLIs against a redirected HOME makes an installed-and-authed agent
 * look unavailable — the Settings checkboxes go dead and it reads like a UI bug. Resolution
 * order:
 *   1. T3MP3ST_AGENT_HOME    — explicit override (a launcher that redirects HOME sets this).
 *   2. os.userInfo().homedir — the real home from the OS user DB (getpwuid), NOT affected by a
 *                              $HOME redirect, so this AUTO-recovers the correct home with no config.
 *   3. os.homedir()          — last-resort fallback.
 * os.homedir()/$HOME is intentionally left untouched for app-config storage (src/config reads it).
 */
export function agentHome(): string {
  const override = (process.env.T3MP3ST_AGENT_HOME || '').trim();
  if (override) return override;
  try {
    const real = userInfo().homedir;
    if (real) return real;
  } catch { /* userInfo can throw in some sandboxes — fall through to homedir() */ }
  return homedir();
}
const expand = (p: string): string => (p.startsWith('~') ? agentHome() + p.slice(1) : p);

/**
 * Resolve a path under the OS-native per-user local app-data root, cross-platform:
 *   - Windows: %LOCALAPPDATA% (e.g. C:\Users\<u>\AppData\Local), where the Hermes desktop app
 *     stores its runtime — its .env / auth lives at %LOCALAPPDATA%\hermes\.env, NOT ~/.hermes/.env.
 *   - POSIX:   <agentHome>/AppData/Local fallback (harmless: the artifact simply won't exist there).
 * PRESENCE-ONLY: callers pass the result to existsSync(); contents are never read.
 */
const localAppData = (rel: string): string =>
  join(process.env.LOCALAPPDATA || join(agentHome(), 'AppData', 'Local'), ...rel.split('/'));

/**
 * Env for a spawned agent CLI. Two adjustments to our own env:
 *   - strip the injected provider keys so the CLI falls back to its OWN native login (not t3mp3st's).
 *   - point HOME (and USERPROFILE on Windows) at the agentHome() so the CLI finds that login even
 *     when t3mp3st itself runs with HOME redirected for app-config storage. Same home the detector
 *     used, so "detected as authed" and "actually authenticates when spawned" stay consistent.
 */
function childEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const k of PROVIDER_ENV_TO_STRIP) delete env[k];
  const home = agentHome();
  env.HOME = home;
  if (process.platform === 'win32') env.USERPROFILE = home;
  return env;
}

export type LocalAgentId = 'claude' | 'codex' | 'hermes';

/** Apply an authoritative bulk selection; single-agent connects remain additive. */
export function syncLocalAgentSelection<T>(
  connected: Map<string, T>,
  selectedIds: string[],
  replace: boolean,
): void {
  if (!replace) return;
  const selected = new Set(selectedIds);
  for (const id of connected.keys()) {
    if (!selected.has(id)) connected.delete(id);
  }
}

interface AgentSpec {
  id: LocalAgentId;
  label: string;
  vendor: string;
  bin: string;
  blurb: string;
  /** how we drive it as a one-shot, non-interactive operator */
  invokeHint: string;
  versionArgs: string[];
  parseVersion: (out: string) => string;
  /** any-of: presence ⇒ authed. PRESENCE ONLY — contents are never read. */
  authArtifacts: string[];
  /** macOS keychain fallback service name */
  keychainService?: string;
  /** build the argv for a headless one-shot prompt */
  oneShot: (prompt: string, model?: string) => string[];
}

const SPECS: AgentSpec[] = [
  {
    id: 'claude',
    label: 'Claude Code',
    vendor: 'Anthropic',
    bin: 'claude',
    blurb: 'Anthropic agentic CLI',
    invokeHint: 'claude -p "<prompt>"',
    versionArgs: ['--version'],
    parseVersion: (o) => (o.match(/[\d]+\.[\d]+(\.[\d]+)?/) || ['?'])[0],
    authArtifacts: ['~/.claude/.credentials.json', '~/.claude.json'],
    keychainService: 'Claude Code-credentials',
    oneShot: (p, m) => ['-p', p, '--output-format', 'text', ...(m ? ['--model', m] : [])],
  },
  {
    id: 'codex',
    label: 'Codex',
    vendor: 'OpenAI',
    bin: 'codex',
    blurb: 'OpenAI Codex CLI',
    invokeHint: 'codex exec "<prompt>"',
    versionArgs: ['--version'],
    parseVersion: (o) => (o.match(/[\d]+\.[\d]+(\.[\d]+)?/) || ['?'])[0],
    authArtifacts: ['~/.codex/auth.json', '~/.config/codex/auth.json'],
    oneShot: (p, m) => ['exec', ...(m ? ['-m', m] : []), p],
  },
  {
    id: 'hermes',
    label: 'Hermes',
    vendor: 'Hermes Agent',
    bin: 'hermes',
    blurb: 'Hermes Agent — tool-calling AI',
    invokeHint: 'hermes -z "<prompt>"  (--yolo only if T3MP3ST_HERMES_YOLO=1)',
    versionArgs: ['--version'],
    parseVersion: (o) => (o.match(/v([\d]+\.[\d]+(\.[\d]+)?)/)?.[1]) || (o.match(/[\d]+\.[\d]+(\.[\d]+)?/) || ['?'])[0],
    // Hermes desktop on Windows stores its login under %LOCALAPPDATA%\hermes\ (NOT ~/.hermes/), so
    // checking only ~/.hermes/ made an authed Windows install read as NOT AUTHED. Presence-only check;
    // ~/.hermes/auth.json is upstream's POSIX/mac auth artifact, kept alongside the Windows paths.
    authArtifacts: ['~/.hermes/.env', '~/.hermes/auth.json', localAppData('hermes/.env'), localAppData('hermes/auth.json')],
    oneShot: (p, m) => ['-z', p, ...(hermesYoloEnabled() ? ['--yolo'] : []), ...(m ? ['-m', m] : [])],
  },
];

export function getSpec(id: string): AgentSpec | undefined {
  return SPECS.find((s) => s.id === id);
}

/**
 * B-06 — Hermes '--yolo' auto-approves EVERY tool call with no confirmation:
 * powerful but dangerous (unattended command exec with no gate). It is OFF by
 * default; the operator must explicitly opt in with T3MP3ST_HERMES_YOLO=1. Safe
 * mode (the default) runs Hermes without the flag so it honors its own approval
 * prompts. Applies to both the one-shot backbone call and the chat path.
 */
export function hermesYoloEnabled(): boolean {
  return /^(1|true|yes|on)$/i.test((process.env.T3MP3ST_HERMES_YOLO || '').trim());
}

export interface AgentDetection {
  id: LocalAgentId;
  label: string;
  vendor: string;
  bin: string;
  blurb: string;
  invokeHint: string;
  installed: boolean;
  path?: string;
  version?: string;
  authed: boolean;
  authMethod?: string; // e.g. "file" or "keychain" — never the secret itself
  ready: boolean;      // installed && authed
}

const isWindows = process.platform === 'win32';
// Kept as a constructed RegExp (not a literal) so the source never embeds a raw CRLF inside a
// regex literal — that repeatedly corrupted this file when edited by line-based patch tooling.
const NEWLINE_RE = new RegExp('\\r?\\n');

/**
 * Windows npm-global CLIs install as shell shims (e.g. `claude.cmd`), NOT bare `.exe`. Node's
 * execFile/spawn only auto-resolve `.exe` via PATHEXT, so `execFile('claude', …)` throws ENOENT
 * even though `claude` runs fine in a shell — which made every npm-installed agent read as
 * "binary not found on PATH". resolveBin() resolves the REAL absolute file path cross-platform:
 *   - Windows: `where.exe` (honors PATHEXT), preferring .exe > .cmd > .bat > first hit.
 *   - POSIX:   `command -v` then `which`.
 * Detection and every spawn then use the resolved path, so a `.cmd` shim launches correctly
 * (see needsShell). Returns undefined only when the bin is genuinely not on PATH.
 */
function resolveBin(bin: string): string | undefined {
  if (isWindows) {
    try {
      const out = execFileSync('where.exe', [bin], { encoding: 'utf8', timeout: 5000 });
      const hits = out.split(NEWLINE_RE).map((h) => h.trim()).filter(Boolean);
      return (
        hits.find((h) => /\.exe$/i.test(h)) ??
        hits.find((h) => /\.cmd$/i.test(h)) ??
        hits.find((h) => /\.bat$/i.test(h)) ??
        hits[0]
      );
    } catch { return undefined; }
  }
  try {
    return execFileSync('command', ['-v', bin], { shell: '/bin/bash', encoding: 'utf8' }).trim() || undefined;
  } catch {
    try { return execFileSync('which', [bin], { encoding: 'utf8' }).trim() || undefined; } catch { return undefined; }
  }
}

/**
 * Windows-safe launcher for a resolved agent binary.
 *
 * A `.cmd`/`.bat` shim can't be spawned with shell:false (Node throws EINVAL on Windows) — it must
 * run through cmd.exe. But hand-rolling `spawn('cmd.exe', ['/d','/s','/c', shim, ...args])` is
 * UNSAFE: cmd.exe re-parses its command tail with its OWN rules and does not honor `\"`-escaping, so
 * the (untrusted, adversarial) prompt reaching argv — claude `-p <prompt>`, codex `exec <prompt>` —
 * can contain `"` + `& | > %VAR%` and break out to execute (the BatBadBut / CVE-2024-1874 class;
 * verified: a `x" & echo PWNED` payload ran).
 *
 * The safe route is Node's OWN `.cmd` handling: `spawn(shim, args, { shell: true })`. On Node
 * >=18.20.2 / >=20.12.2 / >=21 (CVE-2024-27980 fix) Node escapes each arg for cmd, so the whole
 * prompt lands as a SINGLE literal argument and cannot break out (verified on Node 24: the same
 * payload arrived intact in %1). Real `.exe`/POSIX binaries spawn directly with shell:false.
 */
function spawnAgent(resolvedBin: string, args: string[], options: import('child_process').SpawnOptions): import('child_process').ChildProcess {
  if (needsShell(resolvedBin)) {
    // shell:true lets Node run the .cmd via cmd.exe WITH its CVE-2024-27980 arg-escaping (safe);
    // the manual cmd.exe wrapper bypassed that escaping and was injectable.
    return spawn(resolvedBin, args, { ...options, shell: true });
  }
  return spawn(resolvedBin, args, { ...options, shell: false });
}

/**
 * True when the resolved binary is a Windows `.cmd`/`.bat` shim (npm global installs land as these).
 * Such a shim can't be spawned with shell:false — it must go through cmd.exe (see spawnAgent, which
 * does so SAFELY via Node's own shell:true `.cmd` arg-escaping). `.exe` and POSIX binaries return false.
 */
function needsShell(resolvedBin: string): boolean {
  return isWindows && /\.(cmd|bat)$/i.test(resolvedBin);
}

function authState(spec: AgentSpec): { authed: boolean; method?: string } {
  for (const a of spec.authArtifacts) {
    if (existsSync(expand(a))) return { authed: true, method: 'file' };
  }
  if (spec.keychainService) {
    try {
      execFileSync('security', ['find-generic-password', '-s', spec.keychainService], { stdio: 'ignore' });
      return { authed: true, method: 'keychain' };
    } catch { /* not in keychain */ }
  }
  return { authed: false };
}

function detectOne(spec: AgentSpec): Promise<AgentDetection> {
  const base = {
    id: spec.id, label: spec.label, vendor: spec.vendor, bin: spec.bin,
    blurb: spec.blurb, invokeHint: spec.invokeHint,
  };
  // POSIX fallback: if neither `command -v` nor `which` resolved it (e.g. a bash-less/busybox image
  // where both are absent) still try the bare name — the OS resolves it against PATH at exec time,
  // and the ENOENT branch below correctly flips a genuinely-absent binary to not-installed. Windows
  // keeps `resolved` authoritative: a bare npm `.cmd` shim name has no safe direct spawn.
  const resolved = resolveBin(spec.bin) || (isWindows ? undefined : spec.bin);
  return new Promise((resolve) => {
    // Not resolvable at all → genuinely not installed.
    if (!resolved) {
      resolve({ ...base, installed: false, authed: false, ready: false });
      return;
    }
    // Found on PATH ⇒ installed. Used when the version probe can't RUN (a synchronous spawn
    // throw like EPERM, or any async error that isn't ENOENT): the binary exists, we just
    // couldn't read its version. Auth is a filesystem/keychain check, so it still works.
    const installedNoVersion = () => {
      const auth = authState(spec);
      resolve({
        ...base, installed: true, path: resolved, version: '?',
        authed: auth.authed, authMethod: auth.method, ready: auth.authed,
      });
    };
    try {
      // Launch the RESOLVED path (a .cmd shim needs a shell; a real .exe does not).
      execFile(resolved, spec.versionArgs, { timeout: 8000, shell: needsShell(resolved) }, (err, stdout) => {
        if (err && (err as NodeJS.ErrnoException).code === 'ENOENT') {
          resolve({ ...base, installed: false, authed: false, ready: false });
          return;
        }
        // even a non-zero exit but no ENOENT means the binary exists
        const version = spec.parseVersion(String(stdout || ''));
        const auth = authState(spec);
        resolve({
          ...base, installed: true, path: resolved, version,
          authed: auth.authed, authMethod: auth.method, ready: auth.authed,
        });
      });
    } catch {
      // execFile can throw SYNCHRONOUSLY (e.g. `spawn EPERM` when child-process creation is
      // restricted). Inside this Promise executor a throw would REJECT the promise, which fails
      // the Promise.allSettled sibling below and — pre-fix, under Promise.all — 500'd the whole
      // /api/agents/local/detect endpoint, blanking the Settings panel to "0/0 installed".
      installedNoVersion();
    }
  });
}

/** Detect every known local agent CLI (installed? authed? ready?). No tokens spent. */
export async function detectLocalAgents(): Promise<AgentDetection[]> {
  // Test/CI hook: T3MP3ST_DISABLE_LOCAL_AGENTS=1 forces a backbone-less server (skip
  // local-agent auto-detection) so key-required / fail-closed paths can be exercised
  // deterministically — used by scripts/arsenal-smoke.mjs for a reproducible run.
  if (/^(1|true|yes|on)$/i.test((process.env.T3MP3ST_DISABLE_LOCAL_AGENTS || '').trim())) return [];
  // allSettled, NOT all: a single agent's detection failure must degrade to "not installed"
  // for that one agent, never reject the whole batch (which 500'd /detect and blanked the UI).
  const settled = await Promise.allSettled(SPECS.map(detectOne));
  return settled.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    const s = SPECS[i];
    return {
      id: s.id, label: s.label, vendor: s.vendor, bin: s.bin, blurb: s.blurb,
      invokeHint: s.invokeHint, installed: false, authed: false, ready: false,
    };
  });
}

export interface AgentRunResult {
  ok: boolean;
  latencyMs: number;
  output: string;
  error?: string;
}

function agentFailureOutput(output: string): string | null {
  const text = output.trim();
  if (/^API call failed\b/i.test(text)) return text.slice(0, 300);
  if (/connection error/i.test(text) && /failed/i.test(text)) return text.slice(0, 300);
  return null;
}

function envTimeoutMs(name: string, fallback: number): number {
  const parsed = Number(process.env[name]);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Drive a connected agent with a one-shot headless prompt (real round-trip — SPENDS the agent's quota).
 * Used by /ping (liveness proof) and /dispatch (actually using the operator).
 */
export function runLocalAgent(
  id: string,
  prompt: string,
  opts: { model?: string; timeoutMs?: number; maxChars?: number } = {},
): Promise<AgentRunResult> {
  const spec = getSpec(id);
  const t0 = Date.now();
  if (!spec) return Promise.resolve({ ok: false, latencyMs: 0, output: '', error: `unknown agent: ${id}` });
  const args = spec.oneShot(prompt, opts.model);
  const timeoutMs = opts.timeoutMs ?? envTimeoutMs('T3MP3ST_LOCAL_AGENT_TIMEOUT_MS', 600000);
  const maxChars = opts.maxChars ?? 4000;
  // child env: provider keys stripped + HOME pinned to the real agent home (see childEnv).
  const env = childEnv();
  // Resolve the real binary path so a Windows .cmd shim launches (fallback to bare name on POSIX).
  const resolvedBin = resolveBin(spec.bin) || spec.bin;
  return new Promise((resolve) => {
    // stdin:'ignore' so the agent doesn't stall waiting on piped input (e.g. `claude -p`'s 3s stdin wait).
    // spawnAgent() launches a Windows .cmd shim SAFELY (cmd.exe argv array, no shell re-parsing of the prompt).
    const child = spawnAgent(resolvedBin, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let errOut = '';
    let done = false;
    const finish = (r: AgentRunResult): void => { if (!done) { done = true; clearTimeout(timer); resolve(r); } };
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* noop */ }
      finish({ ok: false, latencyMs: Date.now() - t0, output: out.trim().slice(0, maxChars), error: `timed out after ${timeoutMs}ms` });
    }, timeoutMs);
    child.stdout?.on('data', (d) => { if (out.length < 1_000_000) out += String(d); });
    child.stderr?.on('data', (d) => { if (errOut.length < 100_000) errOut += String(d); });
    child.on('error', (e) => finish({ ok: false, latencyMs: Date.now() - t0, output: '', error: (e as Error).message }));
    child.on('close', (code) => {
      const latencyMs = Date.now() - t0;
      const output = out.trim().slice(0, maxChars);
      const semanticError = agentFailureOutput(output);
      if (code === 0 && !semanticError) finish({ ok: true, latencyMs, output });
      else if (semanticError) finish({ ok: false, latencyMs, output, error: semanticError });
      else finish({ ok: false, latencyMs, output, error: (errOut.trim() || `exited with code ${code}`).slice(0, 300) });
    });
  });
}

/** A cheap liveness probe — asks the agent to echo a token. SPENDS a tiny bit of the agent's quota. */
export function pingLocalAgent(id: string, prompt?: string, timeoutMs?: number): Promise<AgentRunResult> {
  return runLocalAgent(id, prompt || 'Reply with exactly the single word: PONG', {
    timeoutMs: timeoutMs ?? 90000,
    maxChars: 400,
  });
}

/**
 * Drive a connected agent as the LLM BACKEND for the mission/operator flow — a long-prompt one-shot
 * that returns ONLY the model's reply text (no CLI banner). Per-agent invocation: claude/codex feed
 * the prompt via STDIN (robust for long planning prompts), codex uses --output-last-message for a
 * clean reply, hermes takes the prompt as an arg. Provider keys are stripped so each CLI uses its own
 * login (no API key needed). Throws on non-zero exit / timeout so the LLMBackbone retry/fallback fires.
 */
export function localAgentChat(id: string, prompt: string, opts: { model?: string; timeoutMs?: number } = {}): Promise<string> {
  const spec = getSpec(id);
  if (!spec) return Promise.reject(new Error(`unknown local agent: ${id}`));
  // child env: provider keys stripped + HOME pinned to the real agent home (see childEnv).
  const env = childEnv();
  const model = opts.model && opts.model !== 'codex-default' && opts.model !== id ? opts.model : undefined;
  const timeoutMs = opts.timeoutMs ?? envTimeoutMs('T3MP3ST_LOCAL_AGENT_TIMEOUT_MS', 600000);

  let args: string[];
  let viaStdin = true;
  let outFile: string | null = null;
  let workDir: string | null = null;
  if (id === 'claude') {
    args = ['-p', '--output-format', 'text', ...(model ? ['--model', model] : [])];
  } else if (id === 'codex') {
    workDir = mkdtempSync(join(tmpdir(), 't3mp3st-codexllm-'));
    outFile = join(workDir, 'reply.txt');
    args = ['exec', '--skip-git-repo-check', '--color', 'never', '--sandbox', 'read-only', '--output-last-message', outFile, ...(model ? ['-m', model] : [])];
  } else { // hermes — takes the prompt as an arg
    args = ['-z', prompt, ...(hermesYoloEnabled() ? ['--yolo'] : []), ...(model ? ['-m', model] : [])];
    viaStdin = false;
  }

  const cleanup = () => { if (workDir) { try { rmSync(workDir, { recursive: true, force: true }); } catch { /* noop */ } } };
  // Resolve the real binary path (Windows .cmd shim vs real .exe). hermes resolves to hermes.exe,
  // so needsShell is false there — its prompt arg never traverses a shell. See needsShell note.
  const resolvedBin = resolveBin(spec.bin) || spec.bin;
  return new Promise((resolve, reject) => {
    // spawnAgent() launches a Windows .cmd shim SAFELY (cmd.exe argv array, no shell re-parsing).
    const child = spawnAgent(resolvedBin, args, { env, stdio: [viaStdin ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    let out = '';
    let errOut = '';
    let done = false;
    const finish = (fn: () => void) => { if (!done) { done = true; clearTimeout(timer); cleanup(); fn(); } };
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* noop */ } finish(() => reject(new Error(`${id} timed out after ${timeoutMs}ms`))); }, timeoutMs);
    child.stdout?.on('data', (d) => { if (out.length < 8_000_000) out += String(d); });
    child.stderr?.on('data', (d) => { if (errOut.length < 200_000) errOut += String(d); });
    child.on('error', (e) => finish(() => reject(e)));
    child.on('close', (code) => {
      let content = out.trim();
      if (outFile) { try { content = (readFileSync(outFile, 'utf8').trim() || content); } catch { /* fall back to stdout */ } }
      finish(() => {
        const semanticError = agentFailureOutput(content);
        if (code === 0 && content && !semanticError) resolve(content);
        else if (semanticError) reject(new Error(semanticError));
        else reject(new Error((errOut.trim() || content || `exited with code ${code}`).slice(0, 800)));
      });
    });
    if (viaStdin && child.stdin) { child.stdin.write(prompt); child.stdin.end(); }
  });
}
