/**
 * The image grid works only from verified descriptors (SPEC-02 REQ-21,
 * REQ-22, REQ-25): previews come from blob URLs of verified bytes, images over
 * the automatic preview limit wait for the user, and a failed image shows its
 * error instead of any received bytes.
 */
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ImageGrid, GRID_MAX_IMAGES } from '../components/ImageGrid';
import { AttachmentViews, LOAD_ERROR_TEXT } from '../attachments/view';
import { AttachmentStore, type AttachmentKey } from '../attachments/store';
import { decodeMessage, type VerifiedDescriptor } from '../attachments/decode';
import { serializeEnvelope, type DescriptorInput } from '../attachments/envelope';
import { padme, sealAttachment, sealedBytes } from '../attachments/format';
import { encodeBase64 } from '../attachments/base64';

const ORIGIN = 'https://relay.example';
const X = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const ALICE = '22222222-2222-4222-8222-222222222222';
const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]);

let n = 0;
const uuid = () => `cccccccc-0000-4000-8000-${(++n).toString(16).padStart(12, '0')}`;

let store: AttachmentStore;
let views: AttachmentViews;
let download: Mock<(id: string) => Promise<Uint8Array>>;
let createObjectURL: Mock<(b: Blob) => string>;
const blobs = new Map<string, Uint8Array>();

async function decoded(descriptors: DescriptorInput[]): Promise<{ key: AttachmentKey; images: VerifiedDescriptor[] }> {
  const messageId = uuid();
  const envelope = serializeEnvelope({ channelId: X, body: '', attachments: descriptors });
  await decodeMessage(
    { origin: ORIGIN, renderedChannelId: X, ownUserId: null },
    { channelId: X, messageId, senderId: ALICE, payload: encodeBase64(Uint8Array.from([1, 2, 3])) },
    { decryptors: { senderKeys: () => envelope }, cache: { get: () => undefined, put: () => {} }, store },
  );
  const key = { origin: ORIGIN, channelId: X, messageId };
  const images = store.get(key)!.attachments.map(a => {
    if (!a.usable) throw new Error('unusable');
    return a.descriptor;
  });
  return { key, images };
}

async function sealedImage(name: string): Promise<DescriptorInput> {
  const s = await sealAttachment(PNG);
  const blobId = uuid();
  blobs.set(blobId, sealedBytes(s));
  return { blobId, key: s.key, noncePrefix: s.noncePrefix, sha256: s.sha256, size: s.size, paddedSize: s.paddedSize, name, mime: 'image/png' };
}

function bigImage(): DescriptorInput {
  const size = 12 * 1024 * 1024;
  return { blobId: uuid(), key: new Uint8Array(32), noncePrefix: new Uint8Array(7), sha256: new Uint8Array(32), size, paddedSize: padme(size), name: 'big.png', mime: 'image/png' };
}

beforeEach(() => {
  store = new AttachmentStore();
  blobs.clear();
  download = vi.fn(async (id: string) => {
    const b = blobs.get(id);
    if (!b) throw Object.assign(new Error('HTTP 404'), { status: 404 });
    return b.slice();
  });
  let k = 0;
  createObjectURL = vi.fn((_b: Blob) => `blob:grid/${++k}`);
  views = new AttachmentViews({ download: (id) => download(id), createObjectURL, revokeObjectURL: () => {} }, store);
});

afterEach(() => {
  cleanup();
  views.dispose();
});

describe('ImageGrid', () => {
  it('renders nothing for fewer than two images', async () => {
    const { key, images } = await decoded([await sealedImage('a.png')]);
    const { container } = render(<ImageGrid entryKey={key} images={images} views={views} />);
    expect(container.firstChild).toBeNull();
  });

  it('shows up to four verified images from blob URLs, each clickable', async () => {
    const descriptors = await Promise.all(['a', 'b', 'c', 'd', 'e'].map(x => sealedImage(`${x}.png`)));
    const { key, images } = await decoded(descriptors);
    const onImageClick = vi.fn();
    const { container } = render(<ImageGrid entryKey={key} images={images} onImageClick={onImageClick} views={views} />);
    await waitFor(() => expect(container.querySelectorAll('img')).toHaveLength(GRID_MAX_IMAGES));
    expect(container.querySelector('.message-image-grid')).toHaveClass('grid-4');
    expect(download).toHaveBeenCalledTimes(GRID_MAX_IMAGES);
    for (const call of createObjectURL.mock.calls) expect(call[0].type).toBe('image/png');
    const cell = container.querySelectorAll('.grid-image')[1];
    fireEvent.click(cell);
    expect(onImageClick).toHaveBeenCalledWith(cell.querySelector('img')!.getAttribute('src'));
  });

  it('does not fetch an image over the automatic preview limit until asked', async () => {
    const { key, images } = await decoded([await sealedImage('a.png'), bigImage()]);
    render(<ImageGrid entryKey={key} images={images} views={views} />);
    await waitFor(() => expect(download).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByText('Load image'));
    await waitFor(() => expect(download).toHaveBeenCalledTimes(2));
  });

  it('a tampered image shows the integrity failure, never its bytes', async () => {
    const a = await sealedImage('a.png');
    const b = await sealedImage('b.png');
    blobs.get(b.blobId)![0] ^= 1;
    const { key, images } = await decoded([a, b]);
    const { container } = render(<ImageGrid entryKey={key} images={images} views={views} />);
    await waitFor(() => expect(screen.getByText(LOAD_ERROR_TEXT.integrity)).toBeInTheDocument());
    // The tampered blob may fail its check before the good one has decrypted.
    await waitFor(() => expect(container.querySelectorAll('img')).toHaveLength(1));
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    for (const call of createObjectURL.mock.calls) expect(call[0].size).toBe(PNG.length);
  });

  it('an unavailable image says so', async () => {
    const a = await sealedImage('a.png');
    const missing = await sealedImage('gone.png');
    blobs.delete(missing.blobId);
    const { key, images } = await decoded([a, missing]);
    render(<ImageGrid entryKey={key} images={images} views={views} />);
    await waitFor(() => expect(screen.getByText(LOAD_ERROR_TEXT.unavailable)).toBeInTheDocument());
  });
});
