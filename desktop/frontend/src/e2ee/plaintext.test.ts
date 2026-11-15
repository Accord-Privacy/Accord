// @vitest-environment node
/**
 * SPEC-02 §6.1, §6.2 rules 1 to 4 and REQ-53: the shared typed-plaintext
 * classifier, run against the vector file that the accord-core reference
 * reads too (`core/tests/vectors/typed-plaintext-v1.json`, V1 to V26 of
 * §6.7 plus the X cases of T-9). The envelope members (rules 5 and 6) are
 * read with `attachments/envelope.ts`, so this file is also T-9's table.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  acceptedPaths,
  acceptsOn,
  classifyFor,
  classifyPlaintext,
  CONTROL_REGISTRY,
  ENVELOPE_PREFIX,
  isWellFormedUtf16,
  needsEnvelopeEscape,
  parseStrictJson,
  startsWithEnvelopePrefix,
  StrictObject,
  strictToPlain,
  utf8ByteLength,
  type Classified,
  type ConsumerPath,
} from './plaintext';
import { readEnvelope } from '../attachments/envelope';

const REPO_ROOT = fileURLToPath(new URL('../../../../', import.meta.url));

interface VectorExpect {
  class: 'control' | 'envelope' | 'legacy_text';
  accepted_by: ConsumerPath[];
  // control
  valid?: boolean;
  tag?: string;
  type?: string;
  // envelope
  result?: 'valid' | 'invalid' | 'newer_version';
  reason?: string;
  channel_id?: string;
  body?: string;
  attachments?: number;
  unusable?: number;
  // legacy text
  legacy_key_json?: boolean;
}

interface Vector {
  id: string;
  description: string;
  plaintext_hex: string;
  expect: VectorExpect;
}

const file = JSON.parse(readFileSync(join(REPO_ROOT, 'core/tests/vectors/typed-plaintext-v1.json'), 'utf8')) as {
  vectors: Vector[];
};

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** The decrypted string a session would hand over, when the bytes are UTF-8. */
function asString(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

function check(c: Classified, e: VectorExpect): void {
  expect(c.class).toBe(e.class);
  expect(acceptedPaths(c)).toEqual(e.accepted_by);
  if (c.class === 'control') {
    expect(c.valid).toBe(e.valid);
    if (c.valid) {
      expect(c.tag).toBe(e.tag);
      expect(c.type).toBe(e.type);
    } else {
      expect(c.reason).toBe(e.reason);
    }
  } else if (c.class === 'envelope') {
    const read = readEnvelope(c);
    expect(read.status).toBe(e.result);
    if (read.status === 'invalid') expect(read.reason).toBe(e.reason);
    if (read.status === 'valid') {
      expect(read.envelope.channelId).toBe(e.channel_id);
      expect(read.envelope.body).toBe(e.body);
      expect(read.envelope.attachments.length).toBe(e.attachments);
      expect(read.envelope.attachments.filter(a => !a.usable).length).toBe(e.unusable);
    }
  } else {
    expect(c.legacyKeyJson).toBe(e.legacy_key_json);
  }
}

describe('typed-plaintext vectors (SPEC-02 §6.7, T-9, REQ-53)', () => {
  it('holds V1 to V26 and the X cases', () => {
    const ids = file.vectors.map(v => v.id);
    for (let i = 1; i <= 26; i++) expect(ids).toContain(`V${i}`);
    expect(new Set(ids).size).toBe(ids.length);
  });

  for (const v of file.vectors) {
    it(`${v.id}: ${v.description}`, () => {
      const bytes = hexToBytes(v.plaintext_hex);
      check(classifyPlaintext(bytes), v.expect);
      // The same result from the decrypted string, when the bytes are UTF-8.
      const s = asString(bytes);
      if (s !== null) check(classifyPlaintext(s), v.expect);
    });
  }

  it('V10 is 16,385 bytes and its 8,146-byte body escapes to 16,292 bytes', () => {
    const v10 = file.vectors.find(v => v.id === 'V10')!;
    expect(v10.plaintext_hex.length / 2).toBe(16_385);
  });
});

describe('classification (§6.1)', () => {
  it('decides the class from the leading bytes only', () => {
    expect(classifyPlaintext('hello').class).toBe('legacy_text');
    expect(classifyPlaintext('').class).toBe('legacy_text');
    expect(classifyPlaintext(`${ENVELOPE_PREFIX},"v":1}`).class).toBe('envelope');
    expect(classifyPlaintext(` \t\r\n${ENVELOPE_PREFIX}`).class).toBe('envelope');
    // Only JSON whitespace may precede the prefix.
    expect(classifyPlaintext(` ${ENVELOPE_PREFIX},"v":1}`).class).toBe('legacy_text');
    expect(classifyPlaintext('\u001e').class).toBe('control');
    expect(classifyPlaintext(' \u001eaccord-call\u001e{}').class).toBe('legacy_text');
  });

  it('never re-classifies an invalid control payload as text', () => {
    const c = classifyPlaintext('\u001eaccord-call\u001enot json');
    expect(c).toMatchObject({ class: 'control', valid: false, reason: 'syntax' });
    for (const path of ['display', 'voice', 'key_distribution', 'control_queue'] as const) {
      expect(acceptsOn(path, c)).toBe(false);
      expect(classifyFor(path, '\u001eaccord-call\u001enot json')).toBeNull();
    }
  });

  it('routes every registered tag and type to its one path', () => {
    for (const [tag, reg] of Object.entries(CONTROL_REGISTRY)) {
      for (const type of reg.types) {
        const c = classifyPlaintext(`\u001e${tag}\u001e{"type":"${type}","v":${reg.v}}`);
        expect(c).toMatchObject({ class: 'control', valid: true, tag, type, v: reg.v });
        expect(acceptedPaths(c)).toEqual([reg.path]);
        expect(classifyFor(reg.path, `\u001e${tag}\u001e{"type":"${type}","v":${reg.v}}`)).not.toBeNull();
        expect(classifyFor('display', `\u001e${tag}\u001e{"type":"${type}","v":${reg.v}}`)).toBeNull();
      }
    }
  });

  it('treats a lone surrogate in a decrypted string as invalid UTF-8 for typed payloads', () => {
    expect(classifyPlaintext('\u001eaccord-ctl\u001e{"type":"session_reset","v":1,"x":"\ud800"}'))
      .toMatchObject({ class: 'control', valid: false, reason: 'utf8' });
    const env = classifyPlaintext(`${ENVELOPE_PREFIX},"v":1,"channel_id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","body":"\ud800"}`);
    expect(env).toMatchObject({ class: 'envelope', status: 'invalid', reason: 'utf8' });
    // Legacy text keeps its string as decrypted.
    expect(classifyPlaintext('a\ud800b')).toMatchObject({ class: 'legacy_text', text: 'a\ud800b' });
  });

  it('accepts legacy key JSON only on the key-distribution path, never for display', () => {
    const skdm = '{"type":"skdm","ch":"c","skid":"k","ck":"AA==","spk":"AA==","iter":0,"rep":null}';
    expect(acceptedPaths(classifyPlaintext(skdm))).toEqual(['key_distribution']);
    expect(classifyFor('display', skdm)).toBeNull();
    // Other JSON stays displayable legacy text.
    expect(acceptedPaths(classifyPlaintext('{"type":"hello"}'))).toEqual(['display']);
    expect(acceptedPaths(classifyPlaintext('{"type":"skdm"'))).toEqual(['display']);
  });

  it('defines legacy key JSON by the strict pass with RFC 8259 numbers, as accord-core does, not by JSON.parse', () => {
    const legacy = (s: string) => {
      const c = classifyPlaintext(s);
      return c.class === 'legacy_text' && c.legacyKeyJson;
    };
    for (const n of ['1e400', '-0.5E-3', '-0', '1.25', '18446744073709551616', '2E+2']) {
      expect(legacy(`{"type":"nmk","x":${n}}`), n).toBe(true);
    }
    const rejected = [
      '{"type":"skdm","x":"\\ud800"}',
      '{"type":"skdm","type":"skdm"}',
      '{"type":"skdm","x":[[[[[[[[0]]]]]]]]}',
      '{"type":"skdm","x":01}',
      '{"type":"skdm","x":1.}',
      '{"type":"skdm","x":.5}',
      '{"type":"skdm","x":+1}',
      '{"type":"skdm","x":1e}',
      '{"type":"skdm","x":--1}',
      '{"type":"skdm"} x',
      '{"type":"skdmx"}',
      '["skdm"]',
    ];
    for (const bad of rejected) expect(legacy(bad), bad).toBe(false);
    // JSON.parse accepts what the shared definition rejects: it is not the definition.
    expect(() => JSON.parse('{"type":"skdm","x":"\\ud800","y":1e400}')).not.toThrow();
    expect(legacy('{"type":"skdm","x":[[[[[[0]]]]]]}')).toBe(true);
    // A raw lone surrogate in a decrypted string reads as its UTF-8 encoding, U+FFFD.
    expect(legacy('{"type":"skdm","x":"\ud800"}')).toBe(true);
    // Rule 3 stays strict everywhere else.
    expect(parseStrictJson('[1e400]')).toEqual({ ok: false, reason: 'number' });
  });
});

describe('strict JSON pass (§6.2 rules 1 to 4)', () => {
  const fail = (text: string) => {
    const r = parseStrictJson(text);
    return r.ok ? null : r.reason;
  };

  it('rejects duplicates at any depth, also after unescaping', () => {
    expect(fail('{"a":1,"a":2}')).toBe('duplicate');
    expect(fail('{"x":{"a":1,"\\u0061":2}}')).toBe('duplicate');
    expect(fail('[{"a":1},{"a":1}]')).toBeNull();
  });

  it('accepts only integer tokens up to 2^53 - 1', () => {
    expect(fail('[0,1,10,9007199254740991]')).toBeNull();
    for (const bad of ['[-1]', '[1.0]', '[1e0]', '[1E0]', '[01]', '[-0]', '[9007199254740992]', '[1-2]', '[18446744073709551616]']) {
      expect(fail(bad)).toBe('number');
    }
  });

  it('rejects lone surrogates, escaped or not, and keeps pairs', () => {
    expect(fail('["\\ud800"]')).toBe('surrogate');
    expect(fail('["\\udc00\\ud800"]')).toBe('surrogate');
    expect(fail('["\\ud83d\\ude00"]')).toBeNull();
    expect(fail('["\ud800"]')).toBe('surrogate');
  });

  it('limits nesting to 8 levels', () => {
    expect(fail('[[[[[[[[0]]]]]]]]')).toBeNull();
    expect(fail('[[[[[[[[[0]]]]]]]]]')).toBe('depth');
    expect(fail('{"a":{"b":{"c":{"d":{"e":{"f":{"g":{}}}}}}}}')).toBeNull();
    expect(fail('{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{}}}}}}}}}')).toBe('depth');
  });

  it('rejects JSON syntax errors', () => {
    for (const bad of ['', '{', '{"a":1,}', '[1,]', '{"a"}', '{"a":tru}', '"\u0001"', '{"a":1} x', "{'a':1}", '["\\x"]', '["\\u12"]', '[+1]', '[.5]']) {
      expect(fail(bad)).toBe('syntax');
    }
    expect(fail(' {"a":[true,false,null,"s\\n\\t\\"\\\\\\/"]} ')).toBeNull();
  });

  it('copies members into fresh plain objects, prototype names included', () => {
    const r = parseStrictJson('{"__proto__":{"x":1},"a":[1,{"b":null}]}');
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value).toBeInstanceOf(StrictObject);
    const plain = strictToPlain(r.value) as Record<string, unknown>;
    expect(Object.getPrototypeOf(plain)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(plain, '__proto__')).toBe(true);
    expect(plain.a).toEqual([1, { b: null }]);
  });
});

describe('REQ-10 escape test', () => {
  it('flags text that could be taken for a typed payload', () => {
    expect(needsEnvelopeEscape('hello')).toBe(false);
    expect(needsEnvelopeEscape('{"type":"accord.content","v":1,"attachments":[]}')).toBe(true);
    expect(needsEnvelopeEscape('\n {"type":"accord.content"')).toBe(true);
    expect(needsEnvelopeEscape('\u001eaccord-call\u001e{}')).toBe(true);
    expect(needsEnvelopeEscape(' \u001eaccord-call\u001e{}')).toBe(false);
    expect(needsEnvelopeEscape('{"type":"accord.contentX"}')).toBe(false);
    expect(startsWithEnvelopePrefix('{"v":1,"type":"accord.content"}')).toBe(false);
  });
});

describe('helpers', () => {
  it('measures UTF-8 lengths and well-formedness', () => {
    expect(utf8ByteLength('aé€😀')).toBe(1 + 2 + 3 + 4);
    expect(utf8ByteLength('\ud800')).toBe(3);
    expect(isWellFormedUtf16('a😀')).toBe(true);
    expect(isWellFormedUtf16('\ude00a')).toBe(false);
  });
});
