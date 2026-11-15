/**
 * SPEC-02 legacy read path: T-27 (opt-in, badged, confirmed, never in a
 * message), T-28 (decrypt-only reader, no bytes on failure, "(name
 * unavailable)", one importer) and T-29 (LEGACY_READ_UNTIL and 410, and the
 * release build that fails while the date is unset).
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { gcm } from '@noble/ciphers/aes.js';
import { api, LegacyRetiredError } from '../api';
import { encryptMessage, getChannelKey } from '../crypto';
import type { LegacyFileRow } from '../types';
import {
  decryptLegacyFile,
  decryptLegacyName,
  LEGACY_NAME_UNAVAILABLE,
  legacyReadAllowed,
  legacyReadUntil,
  resetLegacyStateForTests,
} from './legacy';
import {
  LEGACY_BADGE_TEXT,
  LEGACY_DECRYPT_FAILED_TEXT,
  LEGACY_RETIRED_TEXT,
  LEGACY_TOGGLE_TEXT,
  LegacyUploads,
  resetLegacyToggleForTests,
} from '../components/LegacyUploads';
import { assertReleaseConfig, isReleaseBuild } from '../releaseChecks';

// jsdom gives import.meta.url no file: scheme; tests run from desktop/frontend.
const SRC = join(process.cwd(), 'src');
const X = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const UPLOADER = '33333333-3333-4333-8333-333333333333';

async function legacyKey(channelId = X): Promise<Uint8Array> {
  return (await getChannelKey(undefined as unknown as CryptoKey, channelId)) as Uint8Array;
}

/** The old client's file layout: IV ‖ ciphertext ‖ tag under the channel key. */
async function legacyBlob(plain: Uint8Array): Promise<Uint8Array> {
  const iv = new Uint8Array(12).fill(5);
  const ct = gcm(await legacyKey(), iv).encrypt(plain);
  const out = new Uint8Array(12 + ct.length);
  out.set(iv);
  out.set(ct, 12);
  return out;
}

async function row(id: string, name: string | null): Promise<LegacyFileRow> {
  return {
    id,
    channel_id: X,
    uploader_id: UPLOADER,
    encrypted_filename: name === null ? '' : await encryptMessage(await legacyKey(), name),
    file_size_bytes: 1040,
    created_at: 1_791_600_000,
  };
}

let list: ReturnType<typeof vi.spyOn>;
let download: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  resetLegacyStateForTests();
  resetLegacyToggleForTests();
  list = vi.spyOn(api, 'listLegacyFiles');
  download = vi.spyOn(api, 'downloadLegacyFile');
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe('T-27 (REQ-27): an opt-in, badged, read-only section', () => {
  it('is hidden by default and calls no legacy route until turned on', async () => {
    list.mockResolvedValue([]);
    render(<LegacyUploads channelId={X} keyPair={null} />);
    expect(screen.getByRole('button', { name: LEGACY_TOGGLE_TEXT })).toBeInTheDocument();
    expect(list).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: LEGACY_TOGGLE_TEXT }));
    await waitFor(() => expect(list).toHaveBeenCalledWith(X, { limit: 50, before: undefined }));
  });

  it('badges every item and labels the uploader as reported by the relay', async () => {
    list.mockResolvedValue([await row('f1', 'report.pdf'), await row('f2', 'notes.txt')]);
    render(<LegacyUploads channelId={X} keyPair={null} memberNames={new Map([[UPLOADER, 'Mallory']])} />);
    fireEvent.click(screen.getByRole('button', { name: LEGACY_TOGGLE_TEXT }));
    await waitFor(() => expect(screen.getAllByTestId('legacy-upload-item')).toHaveLength(2));
    expect(screen.getAllByText(LEGACY_BADGE_TEXT)).toHaveLength(2);
    expect(screen.getAllByText(/Uploaded by Mallory, according to the relay/)).toHaveLength(2);
    expect(screen.getByText('report')).toBeInTheDocument();
    expect(screen.getByText('.pdf')).toBeInTheDocument();
    // No action stages an item in the composer, attaches it or re-shares it (OD-40).
    const labels = screen.getAllByRole('button').map(b => b.textContent);
    expect(labels.sort()).toEqual(['Download', 'Download', 'Hide']);
  });

  it('asks for confirmation before downloading; Cancel sends no request', async () => {
    list.mockResolvedValue([await row('f1', 'report.pdf')]);
    const save = vi.fn(async () => 'saved' as const);
    render(<LegacyUploads channelId={X} keyPair={null} save={save} />);
    fireEvent.click(screen.getByRole('button', { name: LEGACY_TOGGLE_TEXT }));
    await waitFor(() => screen.getByText('Download'));
    fireEvent.click(screen.getByText('Download'));
    expect(screen.getByRole('dialog')).toHaveTextContent(LEGACY_BADGE_TEXT);
    fireEvent.click(screen.getByText('Cancel'));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(download).not.toHaveBeenCalled();
    expect(save).not.toHaveBeenCalled();
  });

  it('a confirmed download decrypts and saves as an octet-stream Blob under the sanitized name', async () => {
    const plain = Uint8Array.from([1, 2, 3, 4, 5]);
    list.mockResolvedValue([await row('f1', 'repo‮rt.pdf')]);
    download.mockResolvedValue(await legacyBlob(plain));
    const save = vi.fn(async (..._args: [string, Blob]) => 'saved' as const);
    render(<LegacyUploads channelId={X} keyPair={null} save={save} />);
    fireEvent.click(screen.getByRole('button', { name: LEGACY_TOGGLE_TEXT }));
    await waitFor(() => screen.getByText('Download'));
    fireEvent.click(screen.getByText('Download'));
    fireEvent.click(screen.getAllByText('Download')[1]);
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    const [name, blob] = save.mock.calls[0];
    expect(name).toBe('report.pdf');
    expect(blob.type).toBe('application/octet-stream');
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(plain);
    expect(download).toHaveBeenCalledWith('f1');
  });
});

describe('T-28 (REQ-28): the decrypt-only reader', () => {
  it('a decryption failure shows an error and releases no bytes', async () => {
    const blob = await legacyBlob(Uint8Array.from([9, 9, 9]));
    blob[20] ^= 1;
    list.mockResolvedValue([await row('f1', 'a.txt')]);
    download.mockResolvedValue(blob);
    const save = vi.fn();
    const createUrl = vi.fn();
    URL.createObjectURL = createUrl;
    render(<LegacyUploads channelId={X} keyPair={null} save={save} />);
    fireEvent.click(screen.getByRole('button', { name: LEGACY_TOGGLE_TEXT }));
    await waitFor(() => screen.getByText('Download'));
    fireEvent.click(screen.getByText('Download'));
    fireEvent.click(screen.getAllByText('Download')[1]);
    await waitFor(() => expect(screen.getByText(LEGACY_DECRYPT_FAILED_TEXT)).toBeInTheDocument());
    expect(save).not.toHaveBeenCalled();
    expect(createUrl).not.toHaveBeenCalled();
    await expect(decryptLegacyFile(null, X, blob)).rejects.toThrow(LEGACY_DECRYPT_FAILED_TEXT);
    await expect(decryptLegacyFile(null, X, new Uint8Array(10))).rejects.toThrow();
  });

  it('an empty name, or one that fails to decrypt, shows "(name unavailable)"', async () => {
    const bad = await row('f2', 'x');
    bad.encrypted_filename = 'AAAA' + bad.encrypted_filename.slice(4);
    list.mockResolvedValue([await row('f1', null), bad]);
    render(<LegacyUploads channelId={X} keyPair={null} />);
    fireEvent.click(screen.getByRole('button', { name: LEGACY_TOGGLE_TEXT }));
    await waitFor(() => expect(screen.getAllByText(LEGACY_NAME_UNAVAILABLE)).toHaveLength(2));
    expect(await decryptLegacyName(null, X, '')).toBeNull();
    expect(await decryptLegacyName(null, X, 'not base64 at all')).toBeNull();
    expect(await decryptLegacyName(null, X, await encryptMessage(await legacyKey(), 'ok.txt'))).toBe('ok.txt');
  });

  it('static: only the legacy section imports the legacy module', () => {
    const importers: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        const p = join(dir, entry);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.(ts|tsx)$/.test(entry) && !/\.test\.tsx?$/.test(entry)) {
          if (/from\s+['"][./]*(attachments\/)?legacy['"]/.test(readFileSync(p, 'utf8'))) importers.push(relative(SRC, p));
        }
      }
    };
    walk(SRC);
    expect(importers).toEqual(['components/LegacyUploads.tsx']);
  });
});

describe('T-29 (REQ-29): the read window ends at LEGACY_READ_UNTIL or on a 410', () => {
  it('after LEGACY_READ_UNTIL: no section and no GET /channels/{id}/files', () => {
    vi.stubEnv('VITE_ACCORD_LEGACY_READ_UNTIL', '2020-01-01');
    expect(legacyReadUntil()).toBe(Date.parse('2020-01-01T00:00:00Z'));
    expect(legacyReadAllowed()).toBe(false);
    render(<LegacyUploads channelId={X} keyPair={null} />);
    expect(screen.getByText(LEGACY_RETIRED_TEXT)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: LEGACY_TOGGLE_TEXT })).toBeNull();
    expect(list).not.toHaveBeenCalled();
  });

  it('before the date, or with no date in a development build, the section is available', () => {
    expect(legacyReadAllowed(Date.parse('2026-01-01'), Date.parse('2027-01-01'))).toBe(true);
    expect(legacyReadAllowed(Date.parse('2027-01-02'), Date.parse('2027-01-01'))).toBe(false);
    expect(legacyReadAllowed(Date.now(), null)).toBe(true);
    expect(legacyReadUntil('2027-13-45x')).toBeNull();
  });

  it('a 410 from the relay: the section reads "no longer available" and stops calling legacy routes', async () => {
    list.mockRejectedValue(new LegacyRetiredError());
    render(<LegacyUploads channelId={X} keyPair={null} />);
    fireEvent.click(screen.getByRole('button', { name: LEGACY_TOGGLE_TEXT }));
    await waitFor(() => expect(screen.getByText(LEGACY_RETIRED_TEXT)).toBeInTheDocument());
    expect(legacyReadAllowed()).toBe(false);
    cleanup();
    render(<LegacyUploads channelId={X} keyPair={null} />);
    expect(screen.getByText(LEGACY_RETIRED_TEXT)).toBeInTheDocument();
    expect(list).toHaveBeenCalledTimes(1);
  });

  it('a release build fails while LEGACY_READ_UNTIL is unset', () => {
    expect(() => assertReleaseConfig({ ACCORD_RELEASE_BUILD: '1' })).toThrow(/VITE_ACCORD_LEGACY_READ_UNTIL/);
    expect(() => assertReleaseConfig({ GITHUB_REF_TYPE: 'tag', GITHUB_REF_NAME: 'v1.2.0' })).toThrow();
    expect(() => assertReleaseConfig({ ACCORD_RELEASE_BUILD: '1', VITE_ACCORD_LEGACY_READ_UNTIL: '2027-02-30' })).toThrow();
    expect(() => assertReleaseConfig({ ACCORD_RELEASE_BUILD: '1', VITE_ACCORD_LEGACY_READ_UNTIL: '2027-11-14' })).not.toThrow();
    // Development and CI builds of branches are not release builds.
    expect(isReleaseBuild({ GITHUB_REF_TYPE: 'branch', GITHUB_REF_NAME: 'main' })).toBe(false);
    expect(() => assertReleaseConfig({})).not.toThrow();
    // vite.config.ts runs the check.
    expect(readFileSync(join(SRC, '../vite.config.ts'), 'utf8')).toMatch(/assertReleaseConfig\(process\.env\)/);
  });
});
