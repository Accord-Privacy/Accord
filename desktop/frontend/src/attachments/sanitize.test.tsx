/**
 * SPEC-02 T-23 (REQ-23, RG-C196): file-name sanitization, the final-extension
 * split, the rendering of names (`components/AttachmentName.tsx`) and the
 * preview allowlist of §6.8.
 */
import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { AttachmentName, NAME_CHANGED_TOOLTIP } from '../components/AttachmentName';
import { utf8ByteLength } from '../e2ee/plaintext';
import {
  blobTypeFor,
  finalExtension,
  previewElementFor,
  sanitizeFileName,
  splitFinalExtension,
} from './sanitize';

const name = (s: string) => sanitizeFileName(s).name;

describe('T-23 sanitizer (REQ-23 steps 1 to 7)', () => {
  it('removes a right-to-left override', () => {
    expect(name('invoice‮fdp.exe')).toBe('invoicefdp.exe');
  });

  it('turns a line separator into a space, keeping the final extension', () => {
    const n = name('invoice.pdf .exe');
    expect(n).toBe('invoice.pdf .exe');
    expect(finalExtension(n)).toBe('.exe');
  });

  it('removes zero-width and byte-order-mark characters', () => {
    expect(name('report﻿​.pdf')).toBe('report.pdf');
  });

  it('removes Hangul fillers and trims the leading dot left behind', () => {
    expect(name('ㅤ.pdf')).toBe('pdf');
  });

  it('replaces path and shell characters', () => {
    expect(name('a/b\\c:d<e>f?.txt')).toBe('a_b_c_d_e_f_.txt');
    expect(name('a"b|c*d')).toBe('a_b_c_d');
  });

  it('falls back to "attachment" for an empty result', () => {
    expect(name('...')).toBe('attachment');
    expect(name('')).toBe('attachment');
    expect(name(' ​‮ ')).toBe('attachment');
  });

  it('truncates to 255 UTF-8 bytes on a code point boundary, keeping the extension', () => {
    const n = name('é'.repeat(300) + '.pdf');
    expect(utf8ByteLength(n)).toBeLessThanOrEqual(255);
    expect(n.endsWith('.pdf')).toBe(true);
    expect(n).toBe('é'.repeat(125) + '.pdf');
    // Four-byte code points are never split.
    const emoji = name('\u{1f600}'.repeat(100));
    expect(utf8ByteLength(emoji)).toBe(252);
    expect([...emoji].every(c => c === '\u{1f600}')).toBe(true);
  });

  it('removes NUL, turns U+0085 into a space, and normalizes to NFC', () => {
    expect(name('a\u0000b\u0085c.txt')).toBe('ab c.txt');
    const nfd = 'été.txt';
    expect(name(nfd)).toBe('été.txt');
    expect(name(nfd)).toBe(nfd.normalize('NFC'));
  });

  it('removes every listed format, control, private-use and ignorable code point', () => {
    const removed = [
      0x061c, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
      0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066, 0x2067, 0x2068, 0x2069, 0x206a, 0x206f,
      0xfeff, 0xfff9, 0xfffa, 0xfffb, 0xe0000, 0xe0001, 0xe0041, 0xe007f, 0xfe00, 0xfe0f, 0xe0100,
      0x115f, 0x1160, 0x3164, 0xffa0, 0x0001, 0x001f, 0x007f, 0x0080, 0x009f, 0xe000, 0xf8ff, 0xf0000,
      0x10ffff, 0xfdd0, 0xffff,
    ];
    for (const cp of removed) {
      expect(name(`a${String.fromCodePoint(cp)}b`), `U+${cp.toString(16)}`).toBe('ab');
    }
  });

  it('turns every White_Space code point into a single space', () => {
    for (const cp of [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000]) {
      expect(name(`a${String.fromCodePoint(cp)}${String.fromCodePoint(cp)}b`), `U+${cp.toString(16)}`).toBe('a b');
    }
  });

  it('replaces lone surrogates with U+FFFD', () => {
    expect(name('a\ud800b\udc00.txt')).toBe('a�b�.txt');
  });

  it('keeps ordinary names, emoji sequences and right-to-left text', () => {
    expect(sanitizeFileName('holiday photo.jpg')).toEqual({ name: 'holiday photo.jpg', changed: false });
    expect(name('שלום.pdf')).toBe('שלום.pdf');
    expect(name('\u{1f468}\u{1f3fd}.png')).toBe('\u{1f468}\u{1f3fd}.png');
  });

  it('reports a change for the tooltip of §8.2', () => {
    expect(sanitizeFileName('a‮b').changed).toBe(true);
    expect(sanitizeFileName('ab').changed).toBe(false);
  });
});

describe('final extension (§6.8)', () => {
  it('is the last dot and what follows, when the dot is not first and at most 16 code points follow', () => {
    expect(finalExtension('a.tar.gz')).toBe('.gz');
    expect(finalExtension('.bashrc')).toBeNull();
    expect(finalExtension('noext')).toBeNull();
    expect(finalExtension('a.' + 'x'.repeat(16))).toBe('.' + 'x'.repeat(16));
    expect(finalExtension('a.' + 'x'.repeat(17))).toBeNull();
    expect(finalExtension('a.' + '\u{1f600}'.repeat(16))).toBe('.' + '\u{1f600}'.repeat(16));
    expect(splitFinalExtension('report.pdf')).toEqual({ stem: 'report', ext: '.pdf' });
    expect(splitFinalExtension('report')).toEqual({ stem: 'report', ext: '' });
  });
});

describe('T-23 / RG-C196 rendering (AttachmentName)', () => {
  it('renders the stem in a dir="auto" isolate and the extension in a separate unclipped ltr isolate', () => {
    const { container } = render(<AttachmentName name={'invoice‮fdp.exe'} />);
    const stem = container.querySelector('.attachment-name-stem')!;
    const ext = container.querySelector('.attachment-name-ext')!;
    expect(stem.tagName).toBe('BDI');
    expect(stem.getAttribute('dir')).toBe('auto');
    expect(stem.textContent).toBe('invoicefdp');
    expect(ext.tagName).toBe('BDI');
    expect(ext.getAttribute('dir')).toBe('ltr');
    expect(ext.textContent).toBe('.exe');
    expect((ext as HTMLElement).style.flexShrink).toBe('0');
    expect((ext as HTMLElement).style.overflow).not.toBe('hidden');
    expect((stem as HTMLElement).style.textOverflow).toBe('ellipsis');
    expect(container.textContent).not.toContain('‮');
    expect(container.querySelector('[title]')?.getAttribute('title')).toBe(NAME_CHANGED_TOOLTIP);
  });

  it('shows .exe for a line-separator name', () => {
    const { container } = render(<AttachmentName name={'invoice.pdf .exe'} />);
    expect(container.querySelector('.attachment-name-ext')!.textContent).toBe('.exe');
    expect(container.textContent).toBe('invoice.pdf .exe');
    expect(container.textContent).not.toContain(' ');
  });

  it('keeps exactly the extension apart for a right-to-left stem', () => {
    const { container } = render(<AttachmentName name={'שלוםעולם.pdf'} />);
    expect(container.querySelector('.attachment-name-ext')!.textContent).toBe('.pdf');
    expect(container.querySelector('.attachment-name-stem')!.textContent).toBe('שלוםעולם');
  });

  it('keeps the last 16 code points of a name without an extension visible', () => {
    const long = 'a'.repeat(40) + '0123456789abcdef';
    const { container } = render(<AttachmentName name={long} />);
    expect(container.querySelector('.attachment-name-tail')!.textContent).toBe('0123456789abcdef');
    expect((container.querySelector('.attachment-name-tail') as HTMLElement).style.flexShrink).toBe('0');
    expect(container.querySelector('.attachment-name-head')!.textContent).toBe('a'.repeat(40));
    expect(container.querySelector('.attachment-name-stem')!.getAttribute('dir')).toBe('auto');
  });

  it('renders names as text, never as markup', () => {
    const { container } = render(<AttachmentName name={'<img src=x onerror=alert(1)>.png'} />);
    expect(container.querySelector('img')).toBeNull();
    expect(container.textContent).toBe('_img src=x onerror=alert(1)_.png');
  });
});

describe('preview allowlist (§6.8, REQ-22)', () => {
  it('maps exactly the listed types to their element and everything else to a download', () => {
    expect(previewElementFor('image/png')).toBe('img');
    expect(previewElementFor('image/webp')).toBe('img');
    expect(previewElementFor('audio/flac')).toBe('audio');
    expect(previewElementFor('video/webm')).toBe('video');
    for (const t of ['image/svg+xml', 'text/html', 'application/pdf', 'image/bmp', 'video/quicktime', '__proto__', 'constructor']) {
      expect(previewElementFor(t)).toBeNull();
      expect(blobTypeFor(t)).toBe('application/octet-stream');
    }
    expect(blobTypeFor('image/png')).toBe('image/png');
  });
});
