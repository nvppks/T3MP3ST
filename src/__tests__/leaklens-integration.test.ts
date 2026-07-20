import { describe, expect, it } from 'vitest';
import {
  buildLeakLensArgs,
  maskSecret,
  parseLeakLensJson,
  runLeakLensScan,
  secretFingerprint,
  type LeakLensProcessResult,
  type LeakLensRunner,
} from '../integrations/leaklens/index.js';
import { redactLeakLensSource } from '../integrations/leaklens/router.js';
import type { ProgramScope } from '../bounty/index.js';

const scope: ProgramScope = {
  program: 'authorized-bounty',
  included: [{ host: 'app.example.test', methods: ['GET'] }],
};

function leakLensOutput(secret: string): string {
  const encoded = Buffer.from(secret).toString('base64');
  return JSON.stringify([{
    ID: 'finding-1',
    RuleID: 'leaklens.http.api-key-header.1',
    Groups: [encoded],
    Matches: [{
      StructuralID: 'match-1',
      RuleName: 'HTTP API key header',
      NamedGroups: { token: encoded },
      Location: { Source: { Start: { Line: 42 } } },
      ValidationResult: { Valid: true },
    }],
  }]);
}

describe('LeakLens integration', () => {
  it('masks and fingerprints secrets without retaining the raw value', () => {
    const secret = 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6';
    const findings = parseLeakLensJson(leakLensOutput(secret), 'https://app.example.test/app.js');

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      findingId: 'finding-1',
      ruleId: 'leaklens.http.api-key-header.1',
      source: 'https://app.example.test/app.js',
      line: 42,
      maskedValue: 'A1b2…O5p6',
      secretSha256: secretFingerprint(secret),
      validation: 'valid',
    });
    expect(JSON.stringify(findings)).not.toContain(secret);
    expect(maskSecret('short')).toBe('***');
  });

  it('redacts credentials and query values from returned source locations', () => {
    const source = redactLeakLensSource('https://user:pass@app.example.test/app.js?token=secret&v=42#fragment');
    expect(source).toContain('token=%5BREDACTED%5D');
    expect(source).toContain('v=%5BREDACTED%5D');
    expect(source).not.toContain('user');
    expect(source).not.toContain('pass');
    expect(source).not.toContain('secret');
    expect(source).not.toContain('fragment');
  });

  it('builds bounded crawler arguments and never enables AI implicitly', () => {
    const args = buildLeakLensArgs({
      kind: 'url',
      targetUrl: 'https://app.example.test/',
      scope,
      crawl: true,
      jsIntel: true,
      rateLimit: 999,
      concurrency: 999,
    });

    expect(args).toContain('--crawl');
    expect(args).toContain('--js-intel');
    expect(args).not.toContain('--ai');
    expect(args[args.indexOf('--crawl-rate-limit') + 1]).toBe('10');
    expect(args[args.indexOf('--crawl-concurrency') + 1]).toBe('4');
  });

  it('rejects out-of-scope URL scans before invoking LeakLens', async () => {
    let called = false;
    const runner: LeakLensRunner = async (): Promise<LeakLensProcessResult> => {
      called = true;
      return { stdout: '[]', stderr: '', exitCode: 0 };
    };

    await expect(runLeakLensScan({
      kind: 'url',
      targetUrl: 'https://evil.example.test/app.js',
      scope,
    }, { runner })).rejects.toThrow(/scope denied/);
    expect(called).toBe(false);
  });

  it('scans a Burp response through a temporary local file and returns only redacted findings', async () => {
    const secret = 'Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4';
    let invokedArgs: string[] = [];
    const runner: LeakLensRunner = async (_command, args): Promise<LeakLensProcessResult> => {
      invokedArgs = args;
      return { stdout: leakLensOutput(secret), stderr: '', exitCode: 0 };
    };

    const result = await runLeakLensScan({
      kind: 'content',
      contentBase64: Buffer.from(`const key = '${secret}';`).toString('base64'),
      sourceUrl: 'https://app.example.test/static/app.js',
      sourceMethod: 'GET',
      fileName: 'app.js',
      jsIntel: true,
      scope,
    }, { runner });

    expect(result.success).toBe(true);
    expect(result.findingCount).toBe(1);
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(invokedArgs).toContain('--no-update-check');
    expect(invokedArgs).not.toContain('--validate');
    expect(invokedArgs.at(-1)).toMatch(/t3mp3st-leaklens-.*app\.js$/);
  });

  it('requires explicit bridge approval before live provider validation', async () => {
    const runner: LeakLensRunner = async () => ({ stdout: '[]', stderr: '', exitCode: 0 });
    await expect(runLeakLensScan({
      kind: 'path',
      targetPath: '.',
      validate: true,
      approvalId: 'operator-approved',
    }, { runner, allowValidation: false })).rejects.toThrow(/validation is disabled/);
  });
});
