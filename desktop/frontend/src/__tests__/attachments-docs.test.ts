// @vitest-environment node
/**
 * SPEC-02 T-46 (REQ-46): the documentation of the version-2 attachment model,
 * worded for the release in which relay R1 and client C1 ship.
 *
 * README.md and SECURITY.md:
 * - make no claim that the relay cannot see files without the §9.4 caveat
 *   (the metadata it still sees);
 * - state that metadata (count, padded size, uploader, channel, downloads);
 * - state the §9.1 authenticity limit (attachments are exactly as authentic as
 *   their message; an injected sender key or an intercepted session can read
 *   and forge them, attributed to the impersonated member);
 * - state the N006 deletion-signal risk (the device's only copy of a key).
 * The nginx example sets a body size, and the other REQ-46 documents and the
 * example configuration describe the version-2 model. Every REQ-46 document
 * (README.md, SECURITY.md, docs/architecture.md, docs/api-reference.md,
 * docs/user-guide.md, docs/SELF-HOSTING.md) states the model, the §9.4
 * metadata, the §9.1 impersonation limit, the N006 deletion-signal risk and
 * the reverse-proxy body-size setting; public statements outside that list
 * (the website, ROADMAP.md) do not contradict them.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const REPO_ROOT = join(process.cwd(), '..', '..');

function read(rel: string): string {
  return readFileSync(join(REPO_ROOT, rel), 'utf8');
}

/** Paragraphs, list items and table rows, with wrapped lines joined. */
function units(md: string): string[] {
  const out: string[] = [];
  for (const block of md.split(/\n\s*\n/)) {
    let current = '';
    for (const line of block.split('\n')) {
      if (/^\s*([-*]|\d+\.|\||#)/.test(line) && current) {
        out.push(current);
        current = line;
      } else {
        current = current ? `${current} ${line.trim()}` : line;
      }
    }
    if (current) out.push(current);
  }
  return out.map(u => u.replace(/\s+/g, ' ').trim());
}

const FILES_WORD = /\b(files?|attachments?)\b/i;
const CANNOT_SEE = /\b(relay|server|operator)\b[^.]{0,80}\b(cannot|can't|can not|never|does not|doesn't)\b[^.]{0,20}\b(see|read|access|decrypt|learn)\b/i;
/** The §9.4 caveat: the metadata the relay still sees. */
const METADATA_CAVEAT = /metadata|padded size|how many/i;

describe('T-46 README.md and SECURITY.md', () => {
  for (const file of ['README.md', 'SECURITY.md']) {
    const doc = read(file);
    const flat = doc.replace(/\s+/g, ' ');

    it(`${file}: no "the relay cannot see files" claim without the metadata caveat`, () => {
      const claims = units(doc).filter(u => CANNOT_SEE.test(u) && FILES_WORD.test(u) && !METADATA_CAVEAT.test(u));
      expect(claims).toEqual([]);
      expect(flat).not.toMatch(/\bfiles (\(attachments\) )?are not end-to-end encrypted\b/i);
      expect(flat).not.toMatch(/not yet end-to-end encrypted:\*\* files/i);
    });

    it(`${file}: states the metadata the relay still sees (§9.4)`, () => {
      for (const [what, re] of [
        ['that a message has attachments and how many', /has attachments(,| and) how many/i],
        ['padded sizes', /padded size/i],
        ['the uploader and upload time', /(by whom|who uploaded it)/i],
        ['the channel', /in which channel/i],
        ['downloads', /(who downloads|which members download)/i],
        ['what it does not see', /(does not see|cannot see)[^.]*(file names|names)[^.]*(types|MIME)/i],
      ] as const) {
        expect(flat, `${file}: ${what}`).toMatch(re);
      }
    });

    it(`${file}: states the authenticity limit (§9.1)`, () => {
      expect(flat).toMatch(/exactly as private and (as )?authentic as (the message that carries them|their message)/i);
      expect(flat).toMatch(/sender key/i);
      expect(flat).toMatch(/intercept/i);
      expect(flat).toMatch(/forge[^.]*attributed to the member it impersonates/i);
    });

    it(`${file}: states the deletion-signal risk (N006)`, () => {
      expect(flat).toMatch(/(deletion and expiry signals|deletion, purge and expiry signals)/i);
      expect(flat).toMatch(/not authenticated/i);
      expect(flat).toMatch(/(the device's only copy|device's only copy) of (the|a file's) key/i);
    });

    it(`${file}: legacy uploads are still described as not end-to-end encrypted`, () => {
      expect(flat).toMatch(/(uploaded before|legacy uploads)[^.]*(not end-to-end encrypted|readable by the relay)/i);
    });
  }

  it('SECURITY.md lists attachment metadata among what the relay can see', () => {
    const doc = read('SECURITY.md');
    const can = doc.slice(doc.indexOf('The relay **can** see'), doc.indexOf('The relay **cannot** see'));
    expect(can).toMatch(/Attachment metadata/);
    const cannot = doc.slice(doc.indexOf('The relay **cannot** see'));
    expect(cannot).toMatch(/Attachment contents, file names, file types, keys and exact sizes/);
  });
});

describe('T-46 the other REQ-46 documents', () => {
  it('docs/SELF-HOSTING.md: the nginx example sets a body size above the relay limit, and Caddy is covered', () => {
    const doc = read('docs/SELF-HOSTING.md');
    const nginx = doc.slice(doc.indexOf('```nginx'), doc.indexOf('```', doc.indexOf('```nginx') + 8));
    const m = /client_max_body_size\s+(\d+)m;/.exec(nginx);
    expect(m, 'client_max_body_size in the nginx example').not.toBeNull();
    expect(Number(m![1]) * 1024 * 1024).toBeGreaterThan(104_857_600);
    expect(doc).toMatch(/Caddy[^.]*no (default )?(request )?body limit/i);
  });

  it('docs/SELF-HOSTING.md and deploy/config.example.toml document every attachment setting (§6.6.4)', () => {
    const doc = read('docs/SELF-HOSTING.md');
    const toml = read('deploy/config.example.toml');
    for (const key of [
      'attachments_dir', 'attachment_max_blob_bytes', 'attachment_pending_ttl_secs', 'attachment_max_pending_per_user',
      'attachment_quota_user_bytes', 'attachment_quota_node_bytes', 'attachments_min_free_bytes',
      'attachment_gc_interval_secs', 'attachment_reconcile_interval_secs', 'legacy_attachments',
      'legacy_attachments_retire_after_days',
    ]) {
      expect(doc, key).toContain('`' + key + '`');
      expect(toml, key).toMatch(new RegExp('^' + key + ' = ', 'm'));
    }
    expect(doc).toContain('purge-legacy-attachments');
  });

  it('docs/api-reference.md documents the section 6.4 and 6.5 contract', () => {
    const doc = read('docs/api-reference.md');
    for (const heading of [
      '### `POST /channels/:id/attachments`',
      '### `GET /attachments/:id`',
      '### `DELETE /attachments/:id`',
      '#### `GET /channels/:id/files`',
    ]) {
      expect(doc, heading).toContain(heading);
    }
    for (const reason of [
      'bad_request', 'forbidden', 'blocked', 'not_found', 'length_required', 'too_large', 'unsupported_media_type',
      'rate_limited', 'slow_mode', 'too_many_pending', 'quota_exceeded', 'storage_full', 'internal',
      'claimed', 'legacy_uploads_removed', 'legacy_retired', 'attachments_not_editable', 'attachment_claim_failed',
      'unavailable_ids', 'attachment_limits', 'attachment_ids', 'attachments/2',
    ]) {
      expect(doc, reason).toContain(reason);
    }
    expect(doc).not.toMatch(/Version-2 attachment routes \(not implemented yet\)/);
    expect(doc).not.toMatch(/multipart\/form-data[\s\S]{0,200}encrypted_filename/);
  });

  it('docs/architecture.md and docs/user-guide.md describe the version-2 model and its limits', () => {
    for (const file of ['docs/architecture.md', 'docs/user-guide.md']) {
      const flat = read(file).replace(/\s+/g, ' ');
      expect(flat, file).toMatch(/random key/i);
      expect(flat, file).toMatch(/as (private and as )?authentic as/i);
      expect(flat, file).toMatch(/padded size/i);
      expect(flat, file).not.toMatch(/\bfiles are not end-to-end encrypted\b/i);
    }
  });
});

const REQ46_DOCS = ['README.md', 'SECURITY.md', 'docs/architecture.md', 'docs/api-reference.md', 'docs/user-guide.md', 'docs/SELF-HOSTING.md'];

describe('T-46 every REQ-46 document states the model and all of its limits', () => {
  for (const file of REQ46_DOCS) {
    const flat = read(file).replace(/\s+/g, ' ');

    it(`${file}: the version-2 model`, () => {
      expect(flat).toMatch(/(new|own|fresh) random (256-bit )?key|random key per file/i);
    });

    it(`${file}: the metadata the relay still sees (§9.4)`, () => {
      expect(flat, 'padded sizes').toMatch(/padded (blob )?sizes?/i);
      expect(flat, 'downloads').toMatch(/who downloads|which members download|downloads and their IP/i);
      expect(flat, 'what it does not see').toMatch(/(does not see|cannot see|but not)[^.]*names[^.]*(types|MIME)/i);
    });

    it(`${file}: the authenticity limit: injected sender keys and intercepted sessions can forge, as the impersonated member (§9.1)`, () => {
      expect(flat).toMatch(/as (private and as )?authentic as (the message that carries them|their message|that message)/i);
      expect(flat).toMatch(/sender key/i);
      expect(flat).toMatch(/intercept/i);
      expect(flat).toMatch(/forge[^.]*attributed to the member it impersonates/i);
    });

    it(`${file}: the deletion-signal risk (N006)`, () => {
      expect(flat).toMatch(/not authenticated|unauthenticated/i);
      expect(flat).toMatch(/only copy of (the|a file's|a DM attachment's) key|DM attachment's only key/i);
    });

    it(`${file}: the reverse-proxy body-size setting`, () => {
      expect(flat).toMatch(/client_max_body_size|request body limit/i);
    });
  }

  it('public statements outside the list do not contradict them', () => {
    for (const file of ['website/index.html', 'ROADMAP.md', ...REQ46_DOCS]) {
      const flat = read(file).replace(/\s+/g, ' ');
      expect(flat, file).not.toMatch(/files and voice are not end-to-end encrypted/i);
      expect(flat, file).not.toMatch(/file sharing (are|is) included but (are|is) not end-to-end encrypted/i);
      expect(flat, file).not.toMatch(/(can|could) (still |also )*read files and relay-mode voice/i);
    }
    expect(read('docs/api-reference.md')).not.toMatch(/file uploads use `multipart\/form-data`/);
    expect(read('docs/api-reference.md')).toMatch(/Attachment blobs are uploaded as `application\/octet-stream`/);
  });
});
