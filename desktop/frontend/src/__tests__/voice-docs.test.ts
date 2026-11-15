// @vitest-environment node
/**
 * SPEC-03 T-28 (D), the part that applies to REQ-28 (a): the documentation
 * correction that ships before the client release.
 *
 * REQ-28 (a) requires README.md, SECURITY.md, docs/architecture.md,
 * GOVERNANCE.md and website/index.html to drop the SRTP, voice key rotation and
 * "IP never exposed" claims, and requires server/static/ to be deleted. These
 * scans check exactly that.
 *
 * The rest of T-28 (ROADMAP.md and the other docs/*.md files, P2P mesh and
 * mobile voice claims, the screen-sharing and api-reference patterns, and the
 * code-comment scans) belongs to REQ-28 (b) and lands with the client release.
 * Some of those patterns contradict the wording that (a) requires, for example
 * the statement that P2P screen sharing reveals IP addresses.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const REPO_ROOT = fileURLToPath(new URL('../../../../', import.meta.url));

/** The files that REQ-28 (a) names. CHANGELOG.md is exempt. */
const REQ28A_FILES = [
  'README.md',
  'SECURITY.md',
  'GOVERNANCE.md',
  'docs/architecture.md',
  'website/index.html',
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
 * headings. Lines wrapped inside a paragraph are joined.
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
  sentences: string[];
  flat: string;
}

function loadDoc(file: string): Doc {
  const raw = readRepoFile(file);
  const text = file.endsWith('.html') ? htmlToText(raw) : raw;
  // Drop bold and code markup so that "**never** has access" still matches.
  const units = toUnits(text).map((unit) => unit.replace(/\*\*|__|`/g, ''));
  return {
    file,
    units,
    sentences: units.flatMap(toSentences),
    flat: units.join(' ').replace(/\s+/g, ' '),
  };
}

const VOICE = /\bvoice\b/i;

/** "SRTP" within one sentence of "voice", unless the sentence says P2P, DTLS-SRTP or unused. */
function srtpVoiceClaims(doc: Doc): string[] {
  const hits: string[] = [];
  doc.sentences.forEach((sentence, i) => {
    if (!/\bSRTP\b/i.test(sentence)) return;
    if (/\bP2P\b|DTLS-SRTP|\bunused\b/i.test(sentence)) return;
    const window = [doc.sentences[i - 1], sentence, doc.sentences[i + 1]];
    if (window.some((s) => s !== undefined && VOICE.test(s))) hits.push(sentence);
  });
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

describe('T-28 (REQ-28 (a)): voice documentation claims', () => {
  const docs = REQ28A_FILES.map(loadDoc);

  const rules: Array<[string, (doc: Doc) => string[]]> = [
    ['SRTP named for voice', srtpVoiceClaims],
    ['voice key rotation claim', rotationClaims],
    ['"IP address is never exposed"', ipNeverExposedClaims],
    ['relay cannot access voice, without the relay-mode qualifier', relayCannotReadVoiceClaims],
  ];

  for (const [name, rule] of rules) {
    it(`no ${name} in the REQ-28 (a) files`, () => {
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
});

describe('T-28 (REQ-28 (a)): stale server/static bundles', () => {
  // T-28 accepts either a deleted directory or one with no file containing
  // `voice_key_exchange`. The bundle tracked at bbf2f17 predates that message
  // (its VoiceChat chunk speaks `voice_packet` and `voice_join`), so the marker
  // check alone would pass on it. The batch deletes the directory
  // (specs/README.md section 2.2 step 0), so this checks that it stays deleted.
  it('server/static/ is deleted', () => {
    expect(existsSync(join(REPO_ROOT, 'server', 'static'))).toBe(false);
  });
});
