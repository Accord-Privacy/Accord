// @vitest-environment node
/**
 * SPEC-01 T-44 (REQ-44), the documentation checklist.
 *
 * - docs/api-reference.md lists every endpoint of SPEC-01 §6.2, the reason
 *   codes of §6.4 and the new WebSocket fields and frames of §6.3;
 * - docs/identity-model.md no longer calls invite-only nodes "already
 *   implemented" while joins by node id were open;
 * - GOVERNANCE.md and SECURITY.md say that the relay enforces admission and
 *   sees join requests;
 * - docs/admin-guide.md documents the new operator flags and the preview
 *   limit behind proxies;
 * - the operator release note in CHANGELOG.md covers the items REQ-44 names.
 *
 * The CLI part of T-44 (the redemption URL builder) is a unit test in
 * accord-cli/src/main.rs.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const REPO_ROOT = fileURLToPath(new URL('../../../../', import.meta.url));

function read(rel: string): string {
  return readFileSync(join(REPO_ROOT, rel), 'utf8');
}

/** Section 6.2 of SPEC-01: every endpoint the API reference must list. */
const ENDPOINTS = [
  'POST /invites/:code/join',
  'POST /nodes/:id/join',
  'POST /nodes/:id/leave',
  'DELETE /nodes/:id/members/:user_id',
  'POST /nodes/:id/invites',
  'GET /nodes/:id/invites',
  'DELETE /invites/:invite_id',
  'DELETE /nodes/:id/invites/:code',
  'GET /invites/:code/preview',
  'PATCH /nodes/:id',
  'GET /nodes',
  'GET /nodes/:id/join-requests',
  'POST /nodes/:id/join-requests/:user_id/approve',
  'POST /nodes/:id/join-requests/:user_id/deny',
  'DELETE /nodes/:id/join-request',
  'GET /nodes/:id/audit-log',
];

/** Section 6.4 of SPEC-01. */
const REASONS = [
  'node_not_found',
  'invite_required',
  'invite_invalid',
  'invite_expired',
  'invite_exhausted',
  'already_member',
  'banned',
  'fingerprint_required',
  'device_banned',
  'device_limit',
  'build_not_allowed',
  'join_requests_full',
  'request_not_found',
  'not_member',
  'owner_cannot_leave',
  'forbidden',
  'invalid_request',
  'rate_limited',
  'unavailable',
];

/** Section 6.3 of SPEC-01: frames and fields. */
const WS_ITEMS = [
  'invite_code?',
  'device_fingerprint_hash?',
  'node_joined',
  'join_pending',
  'join_failed',
  'node_left',
  'leave_failed',
  'join_request_created',
  'join_request_denied',
  'request_id',
  'features',
  'admission/1',
];

describe('T-44 docs/api-reference.md', () => {
  const doc = read('docs/api-reference.md');

  it('has a heading for every endpoint of section 6.2', () => {
    for (const endpoint of ENDPOINTS) {
      expect(doc, endpoint).toContain('### `' + endpoint + '`');
    }
  });

  it('lists every reason code of section 6.4', () => {
    for (const reason of REASONS) {
      expect(doc, reason).toMatch(new RegExp('\\| `' + reason + '` \\|'));
    }
    expect(doc).toContain('"reason"');
    expect(doc).toContain('retry_after');
  });

  it('documents the new WebSocket fields and frames', () => {
    const ws = doc.slice(doc.indexOf('## WebSocket API'));
    for (const item of WS_ITEMS) {
      expect(ws, item).toContain(item);
    }
  });

  it('documents the strict invite body, the aliases and admission_since', () => {
    for (const field of ['expires_in_seconds', 'expires_in_hours', 'expires_hours', '"code"', '"uses"', 'admission_since', 'join_policy']) {
      expect(doc, field).toContain(field);
    }
  });
});

describe('T-44 identity model, governance and security docs', () => {
  it('drops the "invite-only nodes, already implemented" claim', () => {
    const doc = read('docs/identity-model.md');
    expect(doc).not.toMatch(/invite-only Nodes \(already implemented\)/i);
    expect(doc).toMatch(/relay now admits a user only with a valid invite/);
  });

  it('GOVERNANCE.md and SECURITY.md say the relay enforces admission and sees join requests', () => {
    for (const file of ['GOVERNANCE.md', 'SECURITY.md']) {
      const doc = read(file).replace(/\s+/g, ' ');
      expect(doc, file).toMatch(/relay (enforces admission|decides who may join|decides who becomes a member)/i);
      expect(doc, file).toMatch(/join requests/i);
      expect(doc, file).toMatch(/sees (join requests|who asked to join)/i);
    }
  });
});

describe('T-44 admin guide and release note', () => {
  it('docs/admin-guide.md documents the operator flags and the preview limit behind proxies', () => {
    const doc = read('docs/admin-guide.md');
    for (const flag of ['--legacy-invite-grace-hours', '--keep-legacy-permanent-invites', '--preview-rate-limit']) {
      expect(doc, flag).toContain('`' + flag + '`');
    }
    expect(doc).toContain('Invite previews behind a reverse proxy');
    expect(doc).toMatch(/loopback/);
    expect(doc).toContain('admission repair failed');
  });

  it('the operator release note covers every REQ-44 item', () => {
    const changelog = read('CHANGELOG.md');
    const start = changelog.indexOf('### Relay admission (SPEC-01) — operator release note');
    expect(start).toBeGreaterThanOrEqual(0);
    const note = changelog.slice(start, changelog.indexOf('\n### ', start + 10)).replace(/\s+/g, ' ');
    for (const [item, pattern] of [
      ['locked accounts', /locked permanently/],
      ['repair log lines', /admission repair: step B5 changed 3 rows/],
      ['expiry of pre-upgrade permanent invites', /stops working 7 days after the first boot/],
      ['new meaning of CREATE_INVITE', /CREATE_INVITE now means "may admit people"/],
      ['reset of legacy role markers', /Legacy role markers are reset/],
      ['fingerprint requirement', /needs a device fingerprint/],
      ['build allowlist on invite redemption', /build allowlist now also applies to invite redemption/],
      ['members who joined by id', /Review your member lists/],
    ] as const) {
      expect(note, item).toMatch(pattern);
    }
  });
});
