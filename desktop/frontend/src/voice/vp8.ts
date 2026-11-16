/**
 * @module voice/vp8
 * The VP8 checks a viewer runs on an authenticated, reassembled frame before
 * it reaches the decoder (SPEC-03 §6.2.9, REQ-49; RFC 6386 §9.1 and §19.1).
 *
 * The frame tag is 3 bytes, little-endian: bit 0 is 0 for a key frame, bits 1
 * to 3 the version, bit 4 `show_frame`, bits 5 to 23 `first_part_size`. A key
 * frame follows it with the start code 9d 01 2a and two 16-bit little-endian
 * fields, each a 14-bit size and 2 scale bits.
 *
 * Pure functions over bytes; nothing here decodes video.
 */

export interface Vp8FrameTag {
  readonly key: boolean;
  readonly version: number;
  readonly showFrame: boolean;
  readonly firstPartSize: number;
}

/** The frame tag, or null for fewer than 3 bytes. */
export function readVp8FrameTag(d: Uint8Array): Vp8FrameTag | null {
  if (d.length < 3) return null;
  const tag = d[0] | (d[1] << 8) | (d[2] << 16);
  return {
    key: (tag & 1) === 0,
    version: (tag >> 1) & 7,
    showFrame: ((tag >> 4) & 1) === 1,
    firstPartSize: (tag >> 5) & 0x7ffff,
  };
}

/**
 * `vp8TagOk`: at least 3 bytes; the tag's key-frame bit agrees with `key`
 * (the authenticated fragment flag); version at most 3; and the frame is
 * longer than `first_part_size` plus 10 bytes for a key frame or plus 3 for
 * an inter frame.
 */
export function vp8TagOk(d: Uint8Array, key: boolean): boolean {
  const t = readVp8FrameTag(d);
  if (!t) return false;
  if (t.key !== key) return false;
  if (t.version > 3) return false;
  return d.length > t.firstPartSize + (key ? 10 : 3);
}

/**
 * `vp8KeySize`: the coded size of a key frame. At least 10 bytes, start code
 * 9d 01 2a at bytes 3 to 5, width and height the low 14 bits of the 16-bit
 * little-endian fields at bytes 6 and 8 (the scale bits are ignored). Null
 * otherwise. Callers check the size against the caps and the fragment header.
 */
export function vp8KeySize(d: Uint8Array): { width: number; height: number } | null {
  if (d.length < 10) return null;
  if (d[3] !== 0x9d || d[4] !== 0x01 || d[5] !== 0x2a) return null;
  return {
    width: (d[6] | (d[7] << 8)) & 0x3fff,
    height: (d[8] | (d[9] << 8)) & 0x3fff,
  };
}
