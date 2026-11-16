// @vitest-environment node
/**
 * SPEC-03 §6.2.9 VP8 checks (REQ-49; RFC 6386 §9.1, §19.1) against the
 * `vp8_headers` section of `core/tests/vectors/amf1-v1.json` (§6.11).
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { readVp8FrameTag, vp8KeySize, vp8TagOk } from './vp8';
import { withinCaps } from './screenFrame';

interface Vp8Vector { name: string; frame: string; key: boolean; width: number | null; height: number | null; expect: 'accept' | 'reject' }

const vectors = (JSON.parse(readFileSync(join(process.cwd(), '..', '..', 'core/tests/vectors/amf1-v1.json'), 'utf8')) as { vp8_headers: Vp8Vector[] }).vp8_headers;

const unhex = (h: string): Uint8Array => Uint8Array.from(h.match(/../g) ?? [], b => parseInt(b, 16));

/** The receiver's check of a reassembled frame against its authenticated fragment header. */
function frameOk(d: Uint8Array, key: boolean, width: number | null, height: number | null): boolean {
  if (!vp8TagOk(d, key)) return false;
  if (!key) return true;
  const size = vp8KeySize(d);
  return !!size && size.width === width && size.height === height && withinCaps(size.width, size.height);
}

describe('vp8_headers vectors', () => {
  it('covers the cases §6.11 lists', () => {
    const names = vectors.map(v => v.name);
    for (const n of ['keyframe_1280x720', 'delta_tag', 'keyframe_tag_says_delta', 'wrong_start_code', 'version_4', 'keyframe_9_bytes', 'first_part_size_too_large', 'width_0', 'scale_bits_set']) {
      expect(names).toContain(n);
    }
  });

  for (const v of vectors) {
    it(`${v.name}: ${v.expect}`, () => {
      expect(frameOk(unhex(v.frame), v.key, v.width, v.height)).toBe(v.expect === 'accept');
    });
  }
});

describe('VP8 frame tag and key-frame header', () => {
  const key = (w: number, h: number, len: number, firstPart: number): Uint8Array => {
    const tag = (1 << 4) | (firstPart << 5);
    const b = new Uint8Array(len);
    b.set([tag & 0xff, (tag >> 8) & 0xff, (tag >> 16) & 0xff, 0x9d, 0x01, 0x2a, w & 0xff, w >> 8, h & 0xff, h >> 8]);
    return b;
  };

  it('reads the tag fields little-endian', () => {
    const t = readVp8FrameTag(key(1280, 720, 200, 0x7ffff >> 4));
    expect(t).toEqual({ key: true, version: 0, showFrame: true, firstPartSize: 0x7ffff >> 4 });
    expect(readVp8FrameTag(new Uint8Array(2))).toBeNull();
  });

  it('accepts versions 0 to 3 and rejects 4 to 7', () => {
    for (let version = 0; version < 8; version++) {
      const b = key(640, 360, 100, 10);
      b[0] = (b[0] & 0xf1) | (version << 1);
      expect(vp8TagOk(b, true), `version ${version}`).toBe(version <= 3);
    }
  });

  it('needs the frame to be longer than first_part_size + 10 (key) or + 3 (delta)', () => {
    expect(vp8TagOk(key(640, 360, 61, 50), true)).toBe(true);
    expect(vp8TagOk(key(640, 360, 60, 50), true)).toBe(false);
    const delta = (len: number, fp: number) => {
      const tag = 1 | (1 << 4) | (fp << 5);
      const b = new Uint8Array(len);
      b.set([tag & 0xff, (tag >> 8) & 0xff, (tag >> 16) & 0xff]);
      return b;
    };
    expect(vp8TagOk(delta(54, 50), false)).toBe(true);
    expect(vp8TagOk(delta(53, 50), false)).toBe(false);
    expect(vp8TagOk(delta(54, 50), true)).toBe(false);
  });

  it('reads 14-bit sizes and ignores the scale bits', () => {
    const b = key(1920, 1080, 100, 10);
    b[7] |= 0xc0;
    b[9] |= 0x80;
    expect(vp8KeySize(b)).toEqual({ width: 1920, height: 1080 });
    expect(vp8KeySize(b.subarray(0, 9))).toBeNull();
    const bad = key(1920, 1080, 100, 10);
    bad[3] = 0x9c;
    expect(vp8KeySize(bad)).toBeNull();
  });
});
