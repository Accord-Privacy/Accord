// @vitest-environment node
/**
 * SPEC-02 T-45 (REQ-45): no client uploads attachments in any way other than
 * SPEC-02 defines.
 *
 * A scan of the desktop (webview and Tauri shell), mobile, CLI and bot-SDK
 * sources, and of `server/static`, finds no POST to `channels/{id}/files` and
 * no multipart file upload; the mobile stubs are gone; `server/static` (the
 * committed bundle with the old upload code) stays deleted. The accord-core
 * reference passes the §6.7 vectors in `core/tests/attachment_vectors.rs`
 * (cargo test), and the TypeScript side in `src/attachments/format.test.ts`.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const REPO_ROOT = join(process.cwd(), '..', '..');

const SOURCE = /\.(ts|tsx|js|mjs|cjs|rs|kt|swift|html)$/;

function walk(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap(name => {
    if (name === 'node_modules' || name === 'target' || name === 'dist' || name === 'build' || name.startsWith('.')) return [];
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) return walk(p);
    return SOURCE.test(name) && !/\.test\.(ts|tsx)$/.test(name) && !p.includes(`${join('src', '__integration__')}`) ? [p] : [];
  });
}

/** POSTs (or multipart bodies) aimed at the legacy upload route. */
function legacyUploads(text: string): string[] {
  const hits: string[] = [];
  const route = /channels\/[^\s"'`]{0,60}\/files\b|"channels\/\{id\}\/files"|channels\/\{id\}\/files/g;
  for (const m of text.matchAll(route)) {
    const window = text.slice(Math.max(0, m.index! - 300), m.index! + 300);
    if (/\bPOST\b|multipart|FormData|@Multipart|httpMethod\s*=\s*"POST"/i.test(window)) hits.push(window.slice(250, 350).replace(/\s+/g, ' '));
  }
  return hits;
}

const SCANNED = ['desktop/frontend/src', 'desktop/src', 'mobile', 'accord-cli/src', 'bot-sdk/src', 'server/static'];

describe('T-45 (REQ-45): attachments only as SPEC-02 defines them', () => {
  it('the scanned trees exist (except server/static, which must not)', () => {
    for (const dir of SCANNED.filter(d => d !== 'server/static')) expect(existsSync(join(REPO_ROOT, dir)), dir).toBe(true);
    expect(existsSync(join(REPO_ROOT, 'server', 'static'))).toBe(false);
  });

  it('no source POSTs to /channels/{id}/files or builds a multipart file upload', () => {
    const offenders: string[] = [];
    for (const dir of SCANNED) {
      for (const file of walk(join(REPO_ROOT, dir))) {
        for (const hit of legacyUploads(readFileSync(file, 'utf8'))) offenders.push(`${relative(REPO_ROOT, file)}: ${hit}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('the scan finds the old upload code when it is present (positive control)', () => {
    expect(legacyUploads('@Multipart\n@POST("channels/{id}/files")\nsuspend fun uploadFile()')).not.toEqual([]);
    expect(legacyUploads('fetch(`${base}/channels/${id}/files`, { method: "POST", body: form })')).not.toEqual([]);
    expect(legacyUploads('fetch(`${base}/channels/${id}/files?limit=50`)')).toEqual([]);
  });

  it('the mobile stubs are gone', () => {
    const android = readFileSync(join(REPO_ROOT, 'mobile/android/app/src/main/java/com/accord/data/service/ApiService.kt'), 'utf8');
    for (const fn of ['uploadFile', 'downloadFile', 'getChannelFiles', 'deleteFile']) {
      expect(android, fn).not.toMatch(new RegExp(`fun\\s+${fn}\\b`));
    }
    const ios = readFileSync(join(REPO_ROOT, 'mobile/ios/Accord/Services/APIService.swift'), 'utf8');
    for (const fn of ['uploadFile', 'fetchChannelFiles']) {
      expect(ios, fn).not.toMatch(new RegExp(`func\\s+${fn}\\b`));
    }
  });

  it('the accord-core reference exists and is checked against the §6.7 vectors', () => {
    expect(existsSync(join(REPO_ROOT, 'core/src/attachment.rs'))).toBe(true);
    const test = readFileSync(join(REPO_ROOT, 'core/tests/attachment_vectors.rs'), 'utf8');
    expect(test).toMatch(/attachments-v1\.json/);
    expect(test).toMatch(/typed-plaintext-v1\.json/);
  });
});
