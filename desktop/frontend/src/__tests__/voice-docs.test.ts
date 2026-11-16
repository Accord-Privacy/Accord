// @vitest-environment node
/**
 * SPEC-03 T-28 (D) and RG-C260-1: the documentation of voice and screen
 * sharing, from the client release on (REQ-28 (b)).
 *
 * Whole-file scans of README.md, SECURITY.md, GOVERNANCE.md, ROADMAP.md,
 * docs/*.md and website/index.html (CHANGELOG.md is exempt) for the claims
 * REQ-28 removes:
 *
 * - "SRTP" within one sentence of "voice", unless the sentence also says
 *   P2P, DTLS-SRTP or unused;
 * - "periodic key rotation", or "30s", "30-second" or "30 second" with
 *   rotation;
 * - "never has access to" or "cannot read" together with voice, without the
 *   relay-mode qualifier;
 * - "P2P mesh";
 * - "WebRTC voice" together with "functional" or "implemented";
 * - "IP address is never exposed";
 * - (A1) "screen shar" within one sentence of "P2P" or "peer-to-peer",
 *   unless the sentence also says "older" or "removed";
 * - (A1) `SetVoiceMode`, `P2PSignal`, `VoiceOffer`, `VoiceAnswer` or
 *   `VoiceIceCandidate` in docs/api-reference.md without "deprecated" or
 *   "retired" in the same table row or paragraph.
 *
 * Required (A1): docs/api-reference.md documents the four screen-sharing
 * messages and the binary messages, says that `GetVoiceMode` reports
 * `relay`, and that legacy `VoicePacket` is refused from the relay release
 * after the client release; docs/user-guide.md has a screen-sharing
 * subsection with the platform statements; GOVERNANCE.md no longer says
 * "never exposed" together with "IP"; the docs describe the stage 0 call
 * keys and P2P as removed, and each of README.md, SECURITY.md,
 * docs/architecture.md, docs/api-reference.md, ROADMAP.md and
 * website/index.html describes mobile voice as not functional, screen
 * sharing with its limits (video only, opt-in watching, `screen/1`, the
 * macOS app viewing only, the metadata the relay sees) and the unused Rust
 * voice modules.
 *
 * Code comments: server/src/handlers.rs and models.rs contain neither
 * "cannot decrypt" nor "cannot interpret", and the doc comments of
 * `VoiceKeyExchange` and `SrtpVoicePacket` do not contain "SRTP" as a word
 * (also checked in Rust by server/tests/spec03_comment_scan_test.rs); the
 * client's voice headers are checked by voice-static.test.ts; server/static
 * is gone.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const REPO_ROOT = fileURLToPath(new URL('../../../../', import.meta.url));

/** The files T-28 scans: the REQ-28 targets and every top-level docs/*.md. CHANGELOG.md is exempt. */
const SCANNED_FILES = [
  'README.md',
  'SECURITY.md',
  'GOVERNANCE.md',
  'ROADMAP.md',
  'website/index.html',
  ...readdirSync(join(REPO_ROOT, 'docs'))
    .filter((f) => f.endsWith('.md'))
    .sort()
    .map((f) => `docs/${f}`),
];

function readRepoFile(rel: string): string {
  return readFileSync(join(REPO_ROOT, rel), 'utf8');
}

/** Text content of an HTML page, with meta `content` attributes included. */
function htmlToText(html: string): string {
  const metaContent = [...html.matchAll(/\bcontent="([^"]*)"/g)].map((m) => m[1]);
  const body = html
    .replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, '\n\n')
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<\/?(?:a|b|code|em|i|small|span|strong)\b[^>]*>/gi, '')
    .replace(/<[^>]+>/g, '\n\n');
  return [...metaContent, body]
    .join('\n\n')
    .replace(/&nbsp;/g, ' ')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

/**
 * Splits a document into units: paragraphs, list items, table rows and
 * headings. Lines wrapped inside a paragraph are joined. Fenced code blocks
 * are one unit each.
 */
function toUnits(text: string): string[] {
  const unquoted = text
    .split('\n')
    .map((line) => line.replace(/^\s*>\s?/, ''))
    .join('\n');
  const units: string[] = [];
  for (const block of unquoted.split(/\n\s*\n/)) {
    const parts: string[] = [];
    for (const line of block.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (parts.length === 0 || /^(?:[-*+]\s|\d+\.\s|\||#{1,6}\s)/.test(trimmed)) {
        parts.push(trimmed);
      } else {
        parts[parts.length - 1] += ' ' + trimmed;
      }
    }
    units.push(...parts);
  }
  return units;
}

function toSentences(unit: string): string[] {
  return unit
    .split(/(?<=[.!?])\s+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

interface Doc {
  file: string;
  units: string[];
  /** Sentences per unit; "within one sentence" never crosses a unit. */
  unitSentences: string[][];
  sentences: string[];
  flat: string;
}

function loadDoc(file: string): Doc {
  const raw = readRepoFile(file);
  const text = file.endsWith('.html') ? htmlToText(raw) : raw;
  // Drop bold and code markup so that "**never** has access" still matches.
  const units = toUnits(text).map((unit) => unit.replace(/\*\*|__|`/g, ''));
  const unitSentences = units.map(toSentences);
  return {
    file,
    units,
    unitSentences,
    sentences: unitSentences.flat(),
    flat: units.join(' ').replace(/\s+/g, ' '),
  };
}

const VOICE = /\bvoice\b/i;
const P2P = /\bP2P\b|peer-to-peer/i;

/** Each sentence with its neighbours in the same unit. */
function* windows(doc: Doc): Generator<{ sentence: string; around: string[] }> {
  for (const sentences of doc.unitSentences) {
    for (let i = 0; i < sentences.length; i++) {
      yield { sentence: sentences[i], around: [sentences[i - 1], sentences[i + 1]].filter((s): s is string => s !== undefined) };
    }
  }
}

/** "SRTP" within one sentence of "voice", unless the sentence says P2P, DTLS-SRTP or unused. */
function srtpVoiceClaims(doc: Doc): string[] {
  const hits: string[] = [];
  for (const { sentence, around } of windows(doc)) {
    if (!/\bSRTP\b/i.test(sentence)) continue;
    if (/\bP2P\b|DTLS-SRTP|\bunused\b/i.test(sentence)) continue;
    if ([sentence, ...around].some((s) => VOICE.test(s))) hits.push(sentence);
  }
  return hits;
}

/** "periodic key rotation", or "30s", "30-second" or "30 second" with rotation. */
function rotationClaims(doc: Doc): string[] {
  const hits = doc.sentences.filter(
    (s) => /\b30\s?s\b|\b30[- ]second\b/i.test(s) && /\brotat/i.test(s),
  );
  if (/periodic key rotation/i.test(doc.flat)) hits.push('periodic key rotation');
  return hits;
}

/** "IP address is never exposed" (and its plural). */
function ipNeverExposedClaims(doc: Doc): string[] {
  const m = doc.flat.match(/\bIP address(?:es)? (?:is|are) never exposed\b/i);
  return m ? [m[0]] : [];
}

/** "never has access to" or "cannot read" together with voice, without the relay-mode qualifier. */
function relayCannotReadVoiceClaims(doc: Doc): string[] {
  return doc.sentences.filter(
    (s) =>
      /never has access to|cannot read/i.test(s) && VOICE.test(s) && !/relay[- ]mode/i.test(s),
  );
}

/** "P2P mesh". */
function p2pMeshClaims(doc: Doc): string[] {
  return doc.sentences.filter((s) => /\bP2P mesh\b/i.test(s));
}

/** "WebRTC voice" together with "functional" or "implemented" (the mobile claim). */
function mobileWebRtcVoiceClaims(doc: Doc): string[] {
  return doc.units.filter((u) => /WebRTC voice/i.test(u) && /\bfunctional\b|\bimplemented\b/i.test(u));
}

/** (A1) "screen shar" within one sentence of "P2P" or "peer-to-peer", unless the sentence also says "older" or "removed". */
function p2pScreenSharingClaims(doc: Doc): string[] {
  const hits: string[] = [];
  const excused = (s: string) => /\bolder\b|\bremoved\b/i.test(s);
  for (const { sentence, around } of windows(doc)) {
    if (!/screen[- ]shar/i.test(sentence)) continue;
    if (P2P.test(sentence) && !excused(sentence)) {
      hits.push(sentence);
      continue;
    }
    for (const n of around) {
      if (P2P.test(n) && !excused(n) && !excused(sentence)) hits.push(`${sentence} / ${n}`);
    }
  }
  return hits;
}

const RETIRED_MESSAGES = ['SetVoiceMode', 'P2PSignal', 'VoiceOffer', 'VoiceAnswer', 'VoiceIceCandidate'];

/** (A1) A retired P2P message in the API reference without "deprecated" or "retired" in the same row or paragraph. */
function undeprecatedP2pMessages(doc: Doc): string[] {
  return doc.units.filter(
    (u) => RETIRED_MESSAGES.some((m) => new RegExp(`\\b${m}\\b`).test(u)) && !/deprecated|retired/i.test(u),
  );
}

describe('T-28 (REQ-28 (b)): voice and screen-sharing documentation claims', () => {
  const docs = SCANNED_FILES.map(loadDoc);

  it('scans the REQ-28 targets and every top-level docs/*.md', () => {
    for (const f of ['README.md', 'SECURITY.md', 'GOVERNANCE.md', 'ROADMAP.md', 'website/index.html', 'docs/architecture.md', 'docs/api-reference.md', 'docs/user-guide.md']) {
      expect(SCANNED_FILES).toContain(f);
    }
    expect(SCANNED_FILES).not.toContain('CHANGELOG.md');
  });

  const rules: Array<[string, (doc: Doc) => string[]]> = [
    ['SRTP named for voice', srtpVoiceClaims],
    ['voice key rotation claim', rotationClaims],
    ['"IP address is never exposed"', ipNeverExposedClaims],
    ['relay cannot access voice, without the relay-mode qualifier', relayCannotReadVoiceClaims],
    ['"P2P mesh"', p2pMeshClaims],
    ['functional or implemented WebRTC voice', mobileWebRtcVoiceClaims],
    ['screen sharing tied to P2P, without "older" or "removed"', p2pScreenSharingClaims],
  ];

  for (const [name, rule] of rules) {
    it(`no ${name} in the scanned files`, () => {
      const violations = docs.flatMap((doc) => rule(doc).map((hit) => `${doc.file}: ${hit}`));
      expect(violations).toEqual([]);
    });
  }

  it('GOVERNANCE.md no longer says "never exposed" together with "IP"', () => {
    const governance = docs.find((d) => d.file === 'GOVERNANCE.md')!;
    const violations = governance.units.filter(
      (unit) => /never exposed/i.test(unit) && /\bIPs?\b/.test(unit),
    );
    expect(violations).toEqual([]);
  });

  describe('docs/api-reference.md', () => {
    const api = docs.find((d) => d.file === 'docs/api-reference.md')!;

    it('marks SetVoiceMode, P2PSignal, VoiceOffer, VoiceAnswer and VoiceIceCandidate as deprecated or retired wherever it names them', () => {
      expect(undeprecatedP2pMessages(api)).toEqual([]);
      for (const m of RETIRED_MESSAGES) expect(api.flat).toContain(m);
    });

    it('documents the screen-sharing messages of §6.12 and the binary messages', () => {
      for (const m of ['ScreenShareStart', 'ScreenShareStop', 'ScreenWatch', 'ScreenKeyframeRequest', 'screen_share_started', 'screen_share_stopped', 'screen_share_rejected', 'screen_watch_rejected', 'screen_keyframe_request', 'screen_watchers', 'screen_sharers', 'screen_limits', 'SCREEN_UP', 'SCREEN_DOWN', 'screen/1']) {
        expect(api.flat).toContain(m);
      }
    });

    it('says that GetVoiceMode and the voice_mode fields report relay', () => {
      expect(api.units.some((u) => /GetVoiceMode/.test(u) && /\brelay\b/.test(u) && /always/i.test(u))).toBe(true);
    });

    it('says that legacy VoicePacket is refused from the relay release after the client release', () => {
      expect(api.units.some((u) => /\bVoicePacket\b/.test(u) && /refus|reject/i.test(u) && /release after the client release/i.test(u))).toBe(true);
    });

    it('describes VoiceKeyExchange and SrtpVoicePacket as call messages and AMF1 frames, not SRTP', () => {
      expect(api.units.some((u) => /\bSrtpVoicePacket\b/.test(u) && /AMF1/.test(u))).toBe(true);
      expect(api.units.some((u) => /\bVoiceKeyExchange\b/.test(u) && /acv1:/.test(u))).toBe(true);
    });
  });

  it('docs/user-guide.md has a screen-sharing subsection with the platform statements', () => {
    const guide = docs.find((d) => d.file === 'docs/user-guide.md')!;
    const start = guide.units.findIndex((u) => /^#{2,4}\s.*screen shar/i.test(u));
    expect(start).toBeGreaterThanOrEqual(0);
    const next = guide.units.findIndex((u, i) => i > start && /^#{1,4}\s/.test(u) && !/^#{4,}/.test(u));
    const section = guide.units.slice(start, next < 0 ? undefined : next).join(' ');
    expect(section).toMatch(/macOS/);
    expect(section).toMatch(/view/i);
    expect(section).toMatch(/Windows/);
    expect(section).toMatch(/Linux/);
    expect(section).toMatch(/end-to-end encrypted/i);
    expect(section).toMatch(/Watch/);
  });

  it('README.md, SECURITY.md and docs/architecture.md describe the call keys, the interim limits, P2P as removed, mobile voice and the unused Rust voice code', () => {
    for (const f of ['README.md', 'SECURITY.md', 'docs/architecture.md']) {
      const flat = docs.find((d) => d.file === f)!.flat;
      expect(flat, f).toMatch(/end-to-end encrypted/i);
      expect(flat, f).toMatch(/Double Ratchet/);
      expect(flat, f).toMatch(/not verified/i);
      expect(flat, f).toMatch(/removed/i);
      expect(flat, f).toMatch(/older (?:clients|versions|apps)/i);
    }
  });

  /** The six files REQ-28 (b) says MUST describe voice, screen sharing, P2P, mobile voice and the unused Rust code. */
  const REQ_28B_FILES = ['README.md', 'SECURITY.md', 'docs/architecture.md', 'docs/api-reference.md', 'ROADMAP.md', 'website/index.html'];

  it('every REQ-28 (b) file describes mobile voice as not working (C132)', () => {
    const mobileVoice = /\bvoice\b[^.]*\b(?:does not|doesn't|not) (?:work|functional)[^.]*\b(?:mobile|iOS|Android)\b|\b(?:mobile|iOS|Android)\b[^.]*\bvoice\b[^.]*\bnot (?:work|functional)|\bmobile voice (?:does not|doesn't) work/i;
    for (const f of REQ_28B_FILES) {
      const doc = docs.find((d) => d.file === f)!;
      expect(doc.sentences.some((s) => mobileVoice.test(s)), f).toBe(true);
    }
  });

  it('every REQ-28 (b) file describes screen sharing with its limits: video only, opt-in watching, needs screen/1, the macOS app only views, and the metadata the relay sees', () => {
    for (const f of REQ_28B_FILES) {
      const flat = docs.find((d) => d.file === f)!.flat;
      expect(flat, `${f}: screen sharing`).toMatch(/screen shar/i);
      expect(flat, `${f}: video only`).toMatch(/video only|only video|no audio|never sound|no sound/i);
      expect(flat, `${f}: opt-in watching`).toMatch(/choose (?:to )?watch|opt-in watching|watching is opt-in|watched only by/i);
      expect(flat, `${f}: availability`).toMatch(/screen\/1|relay that (?:supports|offers) encrypted screen sharing/i);
      expect(flat, `${f}: platform`).toMatch(/macOS app can (?:only )?(?:watch|view)|viewing only in the macOS app|macOS app[^.]*watch but not share/i);
      expect(flat, `${f}: metadata`).toMatch(/who shares|who watches|sizes? and (?:their )?timing/i);
    }
  });

  it('every REQ-28 (b) file names the Rust voice modules as unused (REQ-30)', () => {
    for (const f of REQ_28B_FILES) {
      const units = docs.find((d) => d.file === f)!.units;
      expect(units.some((u) => /srtp/i.test(u) && /p2p_voice/.test(u) && /jitter_buffer/.test(u) && /\bunused\b/i.test(u)), f).toBe(true);
    }
  });
});

describe('T-28 (REQ-28): code comments', () => {
  const server = (rel: string) => readRepoFile(join('server', 'src', rel));

  it('server/src/handlers.rs and models.rs say neither "cannot decrypt" nor "cannot interpret"', () => {
    for (const f of ['handlers.rs', 'models.rs']) {
      const text = server(f).toLowerCase().replace(/\s*\n\s*(?:\/\/[/!]?)?\s*/g, ' ');
      expect(text, f).not.toContain('cannot decrypt');
      expect(text, f).not.toContain('cannot interpret');
    }
  });

  it('the doc comments of VoiceKeyExchange and SrtpVoicePacket do not say SRTP', () => {
    const lines = server('models.rs').split('\n');
    for (const variant of ['VoiceKeyExchange', 'SrtpVoicePacket']) {
      const start = lines.findIndex((l) => l.trim() === `${variant} {`);
      expect(start, variant).toBeGreaterThan(0);
      const docs: string[] = [];
      for (let i = start - 1; i >= 0; i--) {
        const t = lines[i].trim();
        if (t.startsWith('///')) docs.push(t);
        else if (!t.startsWith('#[')) break;
      }
      for (let i = start + 1; i < lines.length && lines[i].trim() !== '},'; i++) {
        if (lines[i].trim().startsWith('///')) docs.push(lines[i].trim());
      }
      expect(docs.join(' '), variant).not.toMatch(/\bSRTP\b/);
    }
  });

  // T-28 accepts either a deleted directory or one with no file containing
  // `voice_key_exchange`. The bundle tracked at bbf2f17 predates that message
  // (its VoiceChat chunk speaks `voice_packet` and `voice_join`), so the marker
  // check alone would pass on it. The batch deletes the directory
  // (specs/README.md section 2.2 step 0), so this checks that it stays deleted.
  it('server/static/ is deleted', () => {
    expect(existsSync(join(REPO_ROOT, 'server', 'static'))).toBe(false);
  });
});
