// @vitest-environment node
/**
 * SPEC-03 static checks over the repository:
 *
 * - T-39 (REQ-39), the CI grep: no non-test file under desktop/frontend/src
 *   contains `RTCPeerConnection`, `stun:`, `turn:`, `P2PSignal`,
 *   `SetVoiceMode` or `sendP2PSignal`; `voice/webrtc.ts` and
 *   `voice/screenshare.ts` do not exist; the production build refuses a
 *   bundle that contains `RTCPeerConnection` outside the reviewed allowlist,
 *   which is empty (`vite.config.ts`).
 * - T-2 (REQ-2), the CI grep: `voice/` and `ws.ts` construct no
 *   `VoicePacket` and export no raw key; `voice/voiceCrypto.ts` is gone.
 * - T-28 (REQ-28), the code-comment part for the client: the voice headers
 *   contain no "server cannot decrypt" and no unqualified "SRTP".
 * - T-30 (REQ-30): the unused Rust voice modules, the voice functions of
 *   `core/src/crypto.rs` and the voice messages of `core/src/protocol.rs`
 *   carry the documentation marker.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const FRONTEND = fileURLToPath(new URL('../../', import.meta.url));
const SRC = join(FRONTEND, 'src');
const REPO = fileURLToPath(new URL('../../../../', import.meta.url));

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

/** Test files: `*.test.ts(x)` and everything under `__tests__/`. */
function isTestFile(path: string): boolean {
  const rel = relative(SRC, path).split('\\').join('/');
  return /\.test\.tsx?$/.test(rel) || rel.startsWith('__tests__/') || rel.includes('/__tests__/');
}

const SOURCE_FILES = walk(SRC).filter(p => /\.(ts|tsx|js|jsx|mjs|cjs|css|html|json)$/.test(p));
const PRODUCTION_FILES = SOURCE_FILES.filter(p => !isTestFile(p));

describe('T-39 (REQ-39) no peer connections in the client', () => {
  it('scans a meaningful set of files', () => {
    expect(PRODUCTION_FILES.length).toBeGreaterThan(50);
    expect(PRODUCTION_FILES.some(p => p.endsWith(join('voice', 'relay.ts')))).toBe(true);
    expect(PRODUCTION_FILES.some(p => p.endsWith(join('voice', 'relay.testkit.ts')))).toBe(true);
  });

  for (const needle of ['RTCPeerConnection', 'stun:', 'turn:', 'P2PSignal', 'SetVoiceMode', 'sendP2PSignal']) {
    it(`no non-test file under src contains ${JSON.stringify(needle)}`, () => {
      const hits = PRODUCTION_FILES.filter(p => readFileSync(p, 'utf8').includes(needle)).map(p => relative(SRC, p));
      expect(hits).toEqual([]);
    });
  }

  it('the P2P files are deleted', () => {
    expect(existsSync(join(SRC, 'voice', 'webrtc.ts'))).toBe(false);
    expect(existsSync(join(SRC, 'voice', 'screenshare.ts'))).toBe(false);
  });

  it('the build fails on RTCPeerConnection in the bundle, with an empty allowlist', () => {
    const config = readFileSync(join(FRONTEND, 'vite.config.ts'), 'utf8');
    expect(config).toMatch(/PEER_CONNECTION_ALLOWLIST: readonly string\[\] = \[\];/);
    expect(config).toMatch(/plugins: \[[^\]]*noPeerConnections\(\)/);
  });

  it('an existing production bundle contains no RTCPeerConnection', () => {
    const dist = join(FRONTEND, 'dist');
    const files = existsSync(dist) ? walk(dist).filter(p => p.endsWith('.js')) : [];
    const hits = files.filter(p => readFileSync(p, 'utf8').includes('RTCPeerConnection')).map(p => relative(dist, p));
    expect(hits).toEqual([]);
  });
});

describe('T-2 (REQ-2) no legacy send path', () => {
  const files = [join(SRC, 'ws.ts'), ...walk(join(SRC, 'voice')).filter(p => /\.tsx?$/.test(p) && !isTestFile(p))];

  it('voice/ and ws.ts construct no VoicePacket and export no raw key', () => {
    for (const f of files) {
      const text = readFileSync(f, 'utf8');
      expect(text, relative(SRC, f)).not.toMatch(/(?<![A-Za-z])VoicePacket\s*:/);
      expect(text, relative(SRC, f)).not.toMatch(/exportKey\(\s*['"`]raw/);
      expect(text, relative(SRC, f)).not.toMatch(/\bsendVoicePacket\b/);
    }
  });

  it('the legacy voice crypto is deleted', () => {
    expect(existsSync(join(SRC, 'voice', 'voiceCrypto.ts'))).toBe(false);
  });
});

describe('T-28 (REQ-28) voice code comments', () => {
  /** The leading comment block of a file. */
  function header(path: string): string {
    const text = readFileSync(path, 'utf8');
    const m = /^\s*(\/\*[\s\S]*?\*\/)/.exec(text.replace(/^\/\/ @vitest-environment \w+\n/, ''));
    return m ? m[1] : '';
  }

  for (const f of ['voice/relay.ts', 'VoiceChat.tsx', 'voice/audio.ts', 'voice/mediaIo.ts']) {
    it(`${f}: no "cannot decrypt" claim and no SRTP claim`, () => {
      const h = header(join(SRC, f));
      expect(h.length).toBeGreaterThan(100);
      expect(h).not.toMatch(/cannot decrypt/i);
      expect(h).not.toMatch(/\bSRTP\b/);
      expect(h).not.toMatch(/P2P mode \(opt-in\)/);
    });
  }
});

describe('T-30 (REQ-30) unused Rust voice code is labelled', () => {
  const MARKER = 'Unused (SPEC-03 REQ-30)';
  const core = (f: string) => readFileSync(join(REPO, 'core', 'src', f), 'utf8');

  for (const f of ['srtp.rs', 'voice.rs', 'p2p_voice.rs', 'jitter_buffer.rs']) {
    it(`core/src/${f} carries the module marker in its module documentation`, () => {
      const docs = core(f).split('\n').filter(l => l.startsWith('//!')).join('\n');
      expect(docs).toContain(MARKER);
      expect(docs).toContain('No shipped Accord client uses this module');
    });
  }

  /** The documentation right above the first line that matches `item`. */
  function docsAbove(text: string, item: RegExp): string {
    const lines = text.split('\n');
    const i = lines.findIndex(l => item.test(l));
    expect(i, String(item)).toBeGreaterThan(0);
    const docs: string[] = [];
    for (let j = i - 1; j >= 0 && /^\s*(\/\/\/|#\[)/.test(lines[j]); j--) docs.unshift(lines[j]);
    return docs.join('\n');
  }

  it('the voice functions and VoiceKey of core/src/crypto.rs', () => {
    const text = core('crypto.rs');
    for (const item of [/pub struct VoiceKey\b/, /pub fn generate_voice_key\(/, /pub fn encrypt_voice_packet\(/, /pub fn decrypt_voice_packet\(/]) {
      expect(docsAbove(text, item)).toContain(MARKER);
    }
  });

  it('the voice message types and payloads of core/src/protocol.rs', () => {
    const text = core('protocol.rs');
    for (const name of ['VoiceJoinPayload', 'VoiceLeavePayload', 'VoicePacketPayload', 'VoiceSpeakingPayload', 'VoiceKeyExchangePayload', 'EncryptedVoicePacketPayload']) {
      expect(docsAbove(text, new RegExp(`pub struct ${name}\\b`))).toContain(MARKER);
    }
    expect(docsAbove(text, /pub fn build_voice_packet\(/)).toContain(MARKER);
    // Both enums' voice variants sit under the marker comment.
    const markerComments = text.split('\n').filter(l => l.includes('// Unused (SPEC-03 REQ-30)'));
    expect(markerComments.length).toBe(2);
  });
});
