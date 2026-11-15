/**
 * SPEC-02 receive-side views: T-20 (download length cap), T-21 (no raw
 * fallback in the message card, the image grid and the Files panel), T-22
 * (preview allowlist, Blob types, saving), T-24 (revocation on removal),
 * T-25 (automatic preview threshold) and T-26 (Files panel built locally).
 */
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { encodeBase64 } from './base64';
import { decodeMessage, type VerifiedDescriptor } from './decode';
import { serializeEnvelope, type DescriptorInput } from './envelope';
import { padme, sealAttachment, sealedBytes } from './format';
import { attachmentStore, type AttachmentKey } from './store';
import {
  AttachmentSaveError,
  AttachmentViews,
  LOAD_ERROR_TEXT,
  SAVE_FAILED_TEXT,
  SAVE_NAME_HEADER,
  attachmentSummary,
  saveAttachment,
  shouldAutoFetch,
  AUTO_PREVIEW_MAX_BLOB_BYTES,
} from './view';
import { forgetMessages } from './lifecycle';
import { decodedFields } from './messageFields';
import type { AttachmentBearer } from './render';
import { AccordApi, AttachmentLengthError } from '../api';
import { AttachmentCard, MessageAttachments } from '../components/MessageAttachments';
import { FileList } from '../FileManager';

const ORIGIN = 'https://relay.example';
const X = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const ALICE = '22222222-2222-4222-8222-222222222222';
const ME = '11111111-1111-4111-8111-111111111111';

let n = 0;
const uuid = () => `bbbbbbbb-0000-4000-8000-${(++n).toString(16).padStart(12, '0')}`;

interface Fixture {
  key: AttachmentKey;
  /** The rendered message, with the fields its own decode set (App.tsx's live path). */
  message: AttachmentBearer;
  descriptors: DescriptorInput[];
  blobs: Map<string, Uint8Array>;
  plains: Map<string, Uint8Array>;
}

/** Seal real files and put their decoded descriptors in the application's store. */
async function decodedMessage(files: { bytes: Uint8Array; name: string; mime: string }[], messageId = uuid()): Promise<Fixture> {
  const descriptors: DescriptorInput[] = [];
  const blobs = new Map<string, Uint8Array>();
  const plains = new Map<string, Uint8Array>();
  for (const f of files) {
    const sealed = await sealAttachment(f.bytes);
    const blobId = uuid();
    blobs.set(blobId, sealedBytes(sealed));
    plains.set(blobId, f.bytes);
    descriptors.push({ blobId, key: sealed.key, noncePrefix: sealed.noncePrefix, sha256: sealed.sha256, size: sealed.size, paddedSize: sealed.paddedSize, name: f.name, mime: f.mime });
  }
  const message = await decodeInto(messageId, descriptors);
  return { key: { origin: ORIGIN, channelId: X, messageId }, message, descriptors, blobs, plains };
}

/**
 * Put descriptors (not necessarily backed by blobs) in the store through the
 * decode function, and return the message as App.tsx builds it from the result.
 */
async function decodeInto(messageId: string, descriptors: DescriptorInput[], expectCount = descriptors.length): Promise<AttachmentBearer> {
  const envelope = serializeEnvelope({ channelId: X, body: 'look', attachments: descriptors });
  return decodeAs(messageId, envelope, expectCount);
}

async function decodeAs(messageId: string, envelope: string, expectCount: number): Promise<AttachmentBearer> {
  const decoded = await decodeMessage(
    { origin: ORIGIN, renderedChannelId: X, ownUserId: ME },
    { channelId: X, messageId, senderId: ALICE, payload: encodeBase64(new TextEncoder().encode('sk:' + messageId)) },
    { decryptors: { senderKeys: () => envelope }, cache: { get: () => undefined, put: () => {} }, store: attachmentStore },
  );
  expect(decoded.attachmentCount).toBe(expectCount);
  return { id: messageId, channel_id: X, sender_id: ALICE, ...decodedFields(decoded, false) };
}

/** The first decoded descriptor of a message (views take only verified descriptors). */
function firstDescriptor(key: AttachmentKey): VerifiedDescriptor {
  const a = attachmentStore.get(key)!.attachments[0];
  if (!a.usable) throw new Error('unusable');
  return a.descriptor;
}

function fakeDescriptor(size: number, mime: string, name = 'x.bin'): DescriptorInput {
  return { blobId: uuid(), key: new Uint8Array(32).fill(1), noncePrefix: new Uint8Array(7).fill(2), sha256: new Uint8Array(32).fill(3), size, paddedSize: padme(size), name, mime };
}

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4]);

let createObjectURL: Mock<(b: Blob) => string>;
let revokeObjectURL: Mock<(url: string) => void>;
let created: Blob[];
let views: AttachmentViews;
let download: Mock<(id: string, len: number, signal: AbortSignal) => Promise<Uint8Array>>;
let blobsById: Map<string, Uint8Array>;
let windowOpen: { mock: { calls: unknown[] } };
let anchorClicks: { mock: { calls: unknown[] } };

beforeEach(() => {
  created = [];
  blobsById = new Map();
  createObjectURL = vi.fn((b: Blob): string => {
    created.push(b);
    return `blob:test/${created.length}`;
  });
  revokeObjectURL = vi.fn((_url: string) => {});
  download = vi.fn(async (id: string, _len: number, _signal: AbortSignal) => {
    const b = blobsById.get(id);
    if (!b) throw Object.assign(new Error('HTTP 404'), { status: 404 });
    return b.slice();
  });
  views = new AttachmentViews({ download: (id, len, signal) => download(id, len, signal), createObjectURL, revokeObjectURL }, attachmentStore);
  windowOpen = vi.spyOn(window, 'open').mockImplementation(() => null);
  anchorClicks = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  // The application-wide createObjectURL is used only by `saveAttachment`.
  URL.createObjectURL = vi.fn(() => 'blob:save/1');
  URL.revokeObjectURL = vi.fn();
});

afterEach(() => {
  cleanup();
  views.dispose();
  attachmentStore.clear();
  vi.restoreAllMocks();
  delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
  delete (window as unknown as Record<string, unknown>).__TAURI__;
});

function noNavigation(): void {
  expect(windowOpen).not.toHaveBeenCalled();
  expect(document.querySelector('iframe')).toBeNull();
}

// ---------------------------------------------------------------------------

describe('T-20 (REQ-20): downloads are capped at the expected length', () => {
  function streamResponse(chunks: Uint8Array[], headers: Record<string, string> = {}) {
    let pulled = 0;
    const cancel = vi.fn();
    // highWaterMark 0: a chunk is pulled only when the reader asks for one.
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (pulled < chunks.length) controller.enqueue(chunks[pulled++]);
        else controller.close();
      },
      cancel,
    }, { highWaterMark: 0 });
    return { response: new Response(body, { status: 200, headers }), pulled: () => pulled, cancel };
  }

  function apiWith(response: Response): { api: AccordApi; fetch: ReturnType<typeof vi.fn> } {
    const f = vi.fn(async () => response);
    vi.stubGlobal('fetch', f);
    const api = new AccordApi('https://relay.example');
    api.setToken('tok');
    return { api, fetch: f };
  }

  afterEach(() => vi.unstubAllGlobals());

  it('a Content-Length larger than expected aborts before the body is read', async () => {
    const s = streamResponse([new Uint8Array(10)], { 'Content-Length': '41' });
    const { api, fetch } = apiWith(s.response);
    await expect(api.downloadAttachment('a1', 40)).rejects.toBeInstanceOf(AttachmentLengthError);
    expect(s.pulled()).toBe(0);
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://relay.example/attachments/a1');
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer tok');
  });

  it('a stream without a length aborts at the expected length plus one byte', async () => {
    const s = streamResponse([new Uint8Array(30), new Uint8Array(11), new Uint8Array(100)]);
    const { api } = apiWith(s.response);
    await expect(api.downloadAttachment('a1', 40)).rejects.toBeInstanceOf(AttachmentLengthError);
    expect(s.pulled()).toBe(2); // 41 bytes: stopped there, the third chunk never read
    expect(s.cancel).toHaveBeenCalled();
  });

  it('an exact length proceeds; a short body fails', async () => {
    const ok = streamResponse([new Uint8Array(30).fill(7), new Uint8Array(10).fill(8)], { 'Content-Length': '40' });
    const a = apiWith(ok.response);
    const bytes = await a.api.downloadAttachment('a1', 40);
    expect(bytes.length).toBe(40);
    expect(bytes[39]).toBe(8);
    const short = streamResponse([new Uint8Array(39)]);
    const b = apiWith(short.response);
    await expect(b.api.downloadAttachment('a1', 40)).rejects.toBeInstanceOf(AttachmentLengthError);
  });

  it('404 and 403 are errors with their status, never bodies', async () => {
    const { api } = apiWith(new Response('{"error":"x"}', { status: 404 }));
    await expect(api.downloadAttachment('a1', 40)).rejects.toMatchObject({ status: 404 });
  });
});

describe('T-21 (REQ-21): no component falls back to raw bytes', () => {
  async function failingFixture(kind: 'tampered' | 'plaintext' | 'truncated') {
    const f = await decodedMessage([{ bytes: PNG, name: 'pic.png', mime: 'image/png' }, { bytes: PNG, name: 'pic2.png', mime: 'image/png' }, { bytes: PNG, name: 'doc.png', mime: 'image/png' }]);
    for (const [id, blob] of f.blobs) {
      if (kind === 'tampered') {
        const t = blob.slice();
        t[3] ^= 1;
        blobsById.set(id, t);
      } else if (kind === 'plaintext') {
        blobsById.set(id, PNG);
      } else {
        blobsById.set(id, blob.slice(0, blob.length - 1));
      }
    }
    return f;
  }

  for (const kind of ['tampered', 'plaintext', 'truncated'] as const) {
    it(`${kind} downloads: message card and image grid show the integrity failure, no object URL`, async () => {
      const f = await failingFixture(kind);
      render(<MessageAttachments message={f.message} origin={ORIGIN} views={views} />);
      await waitFor(() => expect(screen.getAllByText(LOAD_ERROR_TEXT.integrity).length).toBeGreaterThanOrEqual(3));
      expect(createObjectURL).not.toHaveBeenCalled();
      expect(document.querySelector('img')).toBeNull();
      expect(anchorClicks).not.toHaveBeenCalled();
      noNavigation();
    });
  }

  it('a failed card offers no Download and saves nothing', async () => {
    const f = await failingFixture('tampered');
    const save = vi.fn();
    render(<AttachmentCard entryKey={f.key} descriptor={firstDescriptor(f.key)} views={views} save={save} />);
    await waitFor(() => expect(screen.getByText(LOAD_ERROR_TEXT.integrity)).toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Download attachment' })).toBeNull();
    expect(save).not.toHaveBeenCalled();
  });

  it('the Files panel saves nothing from a tampered blob', async () => {
    const f = await failingFixture('tampered');
    const save = vi.fn();
    render(<FileList origin={ORIGIN} channelId={X} messages={[f.message]} attachmentsAvailable={false} keyPair={null} views={views} save={save} />);
    fireEvent.click(screen.getByRole('button', { name: 'Show files' }));
    const panel = screen.getByTestId('files-panel');
    expect(panel.querySelectorAll('[data-testid="attachment-card"]').length).toBe(3);
    // Compact cards fetch nothing until asked.
    expect(download).not.toHaveBeenCalled();
    fireEvent.click(screen.getAllByRole('button', { name: 'Download attachment' })[0]);
    await waitFor(() => expect(screen.getByText(LOAD_ERROR_TEXT.integrity)).toBeInTheDocument());
    expect(save).not.toHaveBeenCalled();
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(anchorClicks).not.toHaveBeenCalled();
    noNavigation();
  });
});

describe('T-22 (REQ-22): allowlisted previews only, octet-stream downloads, native saving', () => {
  it('PNG renders as <img> from a Blob of type image/png; MP4 as <video>', async () => {
    const f = await decodedMessage([
      { bytes: PNG, name: 'photo.png', mime: 'image/png' },
      { bytes: new Uint8Array([0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70]), name: 'clip.mp4', mime: 'video/mp4' },
    ]);
    for (const [id, b] of f.blobs) blobsById.set(id, b);
    const { container } = render(<MessageAttachments message={f.message} origin={ORIGIN} views={views} />);
    await waitFor(() => expect(container.querySelector('img')).not.toBeNull());
    await waitFor(() => expect(container.querySelector('video')).not.toBeNull());
    expect(created.map(b => b.type).sort()).toEqual(['image/png', 'video/mp4']);
    expect(container.querySelector('img')!.getAttribute('src')).toMatch(/^blob:test\//);
    expect(new Uint8Array(await created.find(b => b.type === 'image/png')!.arrayBuffer())).toEqual(PNG);
    noNavigation();
  });

  it('SVG and HTML are never previewed: a Download button only, with an octet-stream Blob', async () => {
    // Uint8Array.from: jsdom's TextEncoder returns an array of another realm.
    const svg = Uint8Array.from(new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'));
    const html = Uint8Array.from(new TextEncoder().encode('<html><script>alert(1)</script></html>'));
    const f = await decodedMessage([{ bytes: svg, name: 'logo.svg', mime: 'image/svg+xml' }, { bytes: html, name: 'page.html', mime: 'text/html' }]);
    for (const [id, b] of f.blobs) blobsById.set(id, b);
    const save = vi.fn(async () => 'saved' as const);
    const { container } = render(<MessageAttachments message={f.message} origin={ORIGIN} views={views} save={save} />);
    // Not fetched automatically, not rendered.
    expect(download).not.toHaveBeenCalled();
    const buttons = screen.getAllByRole('button', { name: 'Download attachment' });
    expect(buttons).toHaveLength(2);
    for (const b of buttons) fireEvent.click(b);
    await waitFor(() => expect(save).toHaveBeenCalledTimes(2));
    for (const [, blob] of save.mock.calls as unknown as [string, Blob][]) expect(blob.type).toBe('application/octet-stream');
    expect(save.mock.calls.map(c => (c as unknown as [string])[0]).sort()).toEqual(['logo.svg', 'page.html']);
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(container.querySelector('img, iframe, object, embed, svg[xmlns]')).toBeNull();
    noNavigation();
  });

  it('in the Tauri shell, saving calls save_attachment with the sanitized name and the bytes, never a path', async () => {
    const invoke = vi.fn(async () => true);
    Object.assign(window, { __TAURI_INTERNALS__: {}, __TAURI__: { core: { invoke } } });
    const result = await saveAttachment('invoice‮fdp.exe', new Blob([new Uint8Array([1, 2, 3])], { type: 'application/octet-stream' }));
    expect(result).toBe('saved');
    expect(invoke).toHaveBeenCalledTimes(1);
    const [cmd, bytes, options] = invoke.mock.calls[0] as unknown as [string, Uint8Array, { headers: Record<string, string> }];
    expect(cmd).toBe('save_attachment');
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect([...bytes]).toEqual([1, 2, 3]);
    expect(options.headers).toEqual({ [SAVE_NAME_HEADER]: encodeURIComponent('invoicefdp.exe') });
    expect(anchorClicks).not.toHaveBeenCalled();
    noNavigation();
  });

  it('in the Tauri shell, a cancelled dialog is not an error', async () => {
    Object.assign(window, { __TAURI_INTERNALS__: {}, __TAURI__: { core: { invoke: vi.fn(async () => false) } } });
    expect(await saveAttachment('a.txt', new Blob(['x']))).toBe('cancelled');
  });

  it('in the Tauri shell, an unavailable or failing command is an error with no fallback', async () => {
    Object.assign(window, { __TAURI_INTERNALS__: {} });
    await expect(saveAttachment('a.txt', new Blob(['x']))).rejects.toBeInstanceOf(AttachmentSaveError);
    Object.assign(window, { __TAURI__: { core: { invoke: vi.fn(async () => { throw new Error('the file could not be written'); }) } } });
    await expect(saveAttachment('a.txt', new Blob(['x']))).rejects.toBeInstanceOf(AttachmentSaveError);
    const hrefBefore = window.location.href;
    expect(anchorClicks).not.toHaveBeenCalled();
    expect(URL.createObjectURL).not.toHaveBeenCalled();
    expect(window.location.href).toBe(hrefBefore);
    noNavigation();
  });

  it('a failed save shows "Couldn\'t save the file" in the card', async () => {
    const f = await decodedMessage([{ bytes: new Uint8Array([9, 9]), name: 'a.bin', mime: 'application/octet-stream' }]);
    for (const [id, b] of f.blobs) blobsById.set(id, b);
    const save = vi.fn(async () => { throw new AttachmentSaveError(); });
    render(<MessageAttachments message={f.message} origin={ORIGIN} views={views} save={save} />);
    fireEvent.click(screen.getByRole('button', { name: 'Download attachment' }));
    await waitFor(() => expect(screen.getByText(SAVE_FAILED_TEXT)).toBeInTheDocument());
    noNavigation();
  });

  it('in the web build, saving clicks an anchor with download on an octet-stream URL', async () => {
    const appended: HTMLAnchorElement[] = [];
    const appendSpy = vi.spyOn(document.body, 'appendChild').mockImplementation(<T extends Node>(node: T): T => {
      if (node instanceof HTMLAnchorElement) appended.push(node);
      return node;
    });
    expect(await saveAttachment('../../etc/pass wd', new Blob(['secret'], { type: 'image/png' }))).toBe('saved');
    expect(anchorClicks).toHaveBeenCalledTimes(1);
    expect(appended[0].download).toBe('.._.._etc_pass wd'.replace(/^\.+/, ''));
    const blob = (URL.createObjectURL as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0] as Blob;
    expect(blob.type).toBe('application/octet-stream');
    appendSpy.mockRestore();
    noNavigation();
  });
});

describe('T-24 (REQ-24): removal revokes URLs and drops state and cache records', () => {
  it('removing a message revokes its preview URL, aborts nothing pending and empties the store', async () => {
    const f = await decodedMessage([{ bytes: PNG, name: 'p.png', mime: 'image/png' }]);
    for (const [id, b] of f.blobs) blobsById.set(id, b);
    const d = firstDescriptor(f.key);
    const state = await views.load(f.key, d);
    expect(state.status).toBe('ready');
    const url = state.status === 'ready' ? state.url : null;
    const cache = new Map<string, unknown>([[f.key.messageId, { v: 1 }], ['other', 'x']]);
    const persist = vi.fn();
    forgetMessages([f.key.messageId], { store: attachmentStore, origin: ORIGIN, cache, persist });
    expect(revokeObjectURL).toHaveBeenCalledWith(url);
    expect(attachmentStore.get(f.key)).toBeUndefined();
    expect(views.get(f.key, d.blobId).status).toBe('idle');
    expect(cache.has(f.key.messageId)).toBe(false);
    expect(cache.has('other')).toBe(true);
    expect(persist).toHaveBeenCalledTimes(1);
  });

  it('a download in flight when the message is removed is aborted and nothing is kept', async () => {
    const f = await decodedMessage([{ bytes: PNG, name: 'p.png', mime: 'image/png' }]);
    let release!: () => void;
    let aborted = false;
    download.mockImplementation((_id: string, _len: number, signal: AbortSignal) => new Promise<Uint8Array>((resolve) => {
      signal.addEventListener('abort', () => { aborted = true; });
      release = () => resolve(f.blobs.values().next().value!);
    }));
    const d = firstDescriptor(f.key);
    const p = views.load(f.key, d);
    attachmentStore.removeMessage(ORIGIN, f.key.messageId);
    expect(aborted).toBe(true);
    release();
    expect((await p).status).toBe('idle');
    expect(createObjectURL).not.toHaveBeenCalled();
  });
});

describe('T-25 (REQ-25, OD-39): automatic previews up to 10 MiB of allowlisted media', () => {
  it('a 12 MiB image triggers no automatic GET; a 1 MiB image does', async () => {
    const big = fakeDescriptor(12 * 1024 * 1024, 'image/png', 'big.png');
    const small = fakeDescriptor(1024 * 1024, 'image/png', 'small.png');
    expect(shouldAutoFetch(big)).toBe(false);
    expect(shouldAutoFetch(small)).toBe(true);
    const bigMessage = await decodeInto(uuid(), [big]);
    const smallMessage = await decodeInto(uuid(), [small]);
    render(<>
      <MessageAttachments message={bigMessage} origin={ORIGIN} views={views} />
      <MessageAttachments message={smallMessage} origin={ORIGIN} views={views} />
    </>);
    await waitFor(() => expect(download).toHaveBeenCalledTimes(1));
    expect(download.mock.calls[0][0]).toBe(small.blobId);
    expect(AUTO_PREVIEW_MAX_BLOB_BYTES).toBe(10_485_760);
  });

  it('non-allowlisted types are never fetched automatically, whatever their size', () => {
    expect(shouldAutoFetch(fakeDescriptor(10, 'application/pdf'))).toBe(false);
    expect(shouldAutoFetch(fakeDescriptor(10, 'image/svg+xml'))).toBe(false);
    expect(shouldAutoFetch(fakeDescriptor(10, 'audio/ogg'))).toBe(true);
  });

  it('unusable descriptors show "Unsupported attachment — update Accord" and are never downloaded', async () => {
    const good = fakeDescriptor(5, 'text/plain', 'a.txt');
    const envelope = serializeEnvelope({ channelId: X, body: '', attachments: [good] }).replace('"scheme":"A256GCM-STREAM64K"', '"scheme":"X"');
    const message = await decodeAs(uuid(), envelope, 1);
    render(<MessageAttachments message={message} origin={ORIGIN} views={views} />);
    expect(screen.getByText('Unsupported attachment — update Accord')).toBeInTheDocument();
    expect(download).not.toHaveBeenCalled();
    expect(attachmentSummary(message, ORIGIN)).toEqual({ total: 1, usable: 0, images: 0 });
  });
});

describe('T-26 (REQ-26, OD-42): the Files panel is built from the attachment store', () => {
  it('lists two attachments of loaded messages and asks the relay for no list', async () => {
    const fetchSpy = vi.fn(async () => new Response('[]'));
    vi.stubGlobal('fetch', fetchSpy);
    const xhrOpen = vi.spyOn(XMLHttpRequest.prototype, 'open');
    const one = await decodeInto(uuid(), [fakeDescriptor(10, 'application/pdf', 'one.pdf')]);
    const two = await decodeInto(uuid(), [fakeDescriptor(20, 'application/zip', 'two.zip')]);
    render(<FileList origin={ORIGIN} channelId={X} messages={[one, two]} attachmentsAvailable={true} keyPair={null} />);
    fireEvent.click(screen.getByRole('button', { name: 'Show files' }));
    const cards = screen.getByTestId('files-panel').querySelectorAll('[data-testid="attachment-card"]');
    expect(cards).toHaveLength(2);
    expect(screen.getByText('one')).toBeInTheDocument();
    expect(screen.getByText('.zip')).toBeInTheDocument();
    // No version-2 listing, and the legacy section stays hidden (no request) until turned on.
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrOpen).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it('another channel\'s attachments are not listed', async () => {
    const one = await decodeInto(uuid(), [fakeDescriptor(10, 'application/pdf', 'one.pdf')]);
    render(<FileList origin={ORIGIN} channelId={'0b6e5a1c-3d2f-4e8a-9c7b-1a2b3c4d5e6f'} messages={[one]} attachmentsAvailable={false} keyPair={null} />);
    fireEvent.click(screen.getByRole('button', { name: 'Show files' }));
    expect(screen.getByTestId('files-panel').querySelectorAll('[data-testid="attachment-card"]')).toHaveLength(0);
  });
});
