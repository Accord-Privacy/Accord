/**
 * SPEC-01 T-43 (REQ-43): the desktop side of relay admission.
 *
 * - invite creation sends `expires_in_seconds` to relays with `admission/1`
 *   and integer `expires_in_hours` otherwise;
 * - the invite list reads `invite_code` and `current_uses`, and revoke uses
 *   `DELETE /invites/<id>`;
 * - every refusal `reason` maps to the messages of SPEC-01 §8, at every
 *   invite-redemption call site;
 * - a forged `node_joined` only reloads the node list: no `StoreSenderKey`
 *   and no NMK send follow;
 * - the node-scoped fingerprint matches an independently computed
 *   HMAC-SHA-256 reference, differs per node, and is sent with redemptions;
 * - the relay-features record comes from `hello` and is forgotten on
 *   disconnect.
 *
 * The welcome card's fallback when the preview fails with 429 is tested in
 * ChatArea.test.tsx.
 */
import { createHmac } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AccordApi, api as sharedApi } from '../api';
import { ApiError } from '../apiError';
import {
  ADMISSION_FEATURE,
  admissionMessage,
  hoursToSeconds,
  inviteCreateBody,
  inviteCreateErrorMessage,
  isAlreadyMember,
  isPreviewUnavailable,
  joinErrorMessage,
  redeemInvite,
  registerAdmissionHandlers,
} from '../admission';
import { NodeSettings } from '../NodeSettings';
import type { Node } from '../types';
import {
  INSTALL_SECRET_KEY,
  NODE_FINGERPRINT_LABEL,
  computeNodeFingerprint,
  getInstallSecret,
  nodeDeviceFingerprint,
} from '../nodeFingerprint';
import { AccordWebSocket } from '../ws';
import { JoinNodeDialog } from '../NodeDiscovery';

const mockFetch = vi.fn();

function jsonResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

function lastBody(): any {
  const init = mockFetch.mock.calls[mockFetch.mock.calls.length - 1][1] as RequestInit;
  return init.body === undefined ? undefined : JSON.parse(init.body as string);
}

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal('fetch', mockFetch);
  localStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── Invite creation, list and revoke ─────────────────────────────────────

describe('T-43 invite creation', () => {
  const NEW_RELAY = [ADMISSION_FEATURE];
  const OLD_RELAY: string[] = [];

  it('sends expires_in_seconds when the relay lists admission/1', async () => {
    const api = new AccordApi('https://relay.test');
    for (const [hours, seconds] of [
      [0.5, 1800],
      [0.1, 360],
      [1, 3600],
      [24, 86400],
      [168, 604800],
    ] as const) {
      mockFetch.mockResolvedValueOnce(jsonResponse(200, { invite_code: 'X', expires_at: 1 }));
      await api.createInviteWithOptions('n1', 'tok', 5, hours, NEW_RELAY);
      expect(lastBody()).toEqual({ max_uses: 5, expires_in_seconds: seconds });
    }
    expect(mockFetch.mock.calls[0][0]).toBe('https://relay.test/nodes/n1/invites');
    expect((mockFetch.mock.calls[0][1] as RequestInit).method).toBe('POST');
  });

  it('sends integer expires_in_hours to a relay without admission/1, rounding 30 minutes up', async () => {
    const api = new AccordApi('https://relay.test');
    for (const [hours, sent] of [
      [0.5, 1],
      [0.1, 1],
      [24, 24],
      [1.5, 2],
    ] as const) {
      mockFetch.mockResolvedValueOnce(jsonResponse(200, { invite_code: 'X' }));
      await api.createInviteWithOptions('n1', 'tok', undefined, hours, OLD_RELAY);
      const body = lastBody();
      expect(body).toEqual({ expires_in_hours: sent });
      expect(Number.isInteger(body.expires_in_hours)).toBe(true);
    }
    // No features known at all behaves like a legacy relay.
    mockFetch.mockResolvedValueOnce(jsonResponse(200, { invite_code: 'X' }));
    await api.createInviteWithOptions('n1', 'tok', undefined, 0.5);
    expect(lastBody()).toEqual({ expires_in_hours: 1 });
  });

  it('never sends the deprecated expires_hours, and sends no body for "never, unlimited"', async () => {
    const api = new AccordApi('https://relay.test');
    mockFetch.mockResolvedValueOnce(jsonResponse(200, { invite_code: 'X' }));
    await api.createInviteWithOptions('n1', 'tok', undefined, undefined, NEW_RELAY);
    expect(lastBody()).toBeUndefined();
    expect(inviteCreateBody(3, 0.5, NEW_RELAY)).not.toHaveProperty('expires_hours');
    expect(inviteCreateBody(3, 0.5, OLD_RELAY)).not.toHaveProperty('expires_hours');
  });

  it('converts hours like the relay does', () => {
    expect(hoursToSeconds(0.5)).toBe(1800);
    expect(hoursToSeconds(0.1)).toBe(360);
    expect(hoursToSeconds(0.01)).toBe(36);
    expect(hoursToSeconds(1 / 3)).toBe(1200);
  });

  it('maps invite-creation failures to the section 8 messages', () => {
    expect(
      inviteCreateErrorMessage(new ApiError('expires_in_seconds out of range', 400, 'invalid_request')),
    ).toBe("Couldn't create invite: expires_in_seconds out of range");
    expect(inviteCreateErrorMessage(new ApiError('Service temporarily unavailable', 503, 'unavailable'))).toBe(
      "Couldn't create invite. Try again.",
    );
  });
});

describe('T-43 invite list and revoke', () => {
  it('reads invite_code and current_uses from the list', async () => {
    const api = new AccordApi('https://relay.test');
    mockFetch.mockResolvedValueOnce(
      jsonResponse(200, {
        invites: [
          {
            id: 'i1', node_id: 'n1', created_by: 'u1', invite_code: 'CODE1', code: 'CODE1',
            max_uses: 5, current_uses: 2, uses: 2, expires_at: 1700003600, created_at: 1700000000,
          },
          // A relay without the aliases (before SPEC-01) sends only these.
          { id: 'i2', invite_code: 'CODE2', max_uses: null, current_uses: 0, expires_at: null, created_at: 1 },
        ],
      }),
    );
    const invites = await api.getNodeInvites('n1', 'tok');
    expect(invites).toEqual([
      { id: 'i1', invite_code: 'CODE1', created_at: 1700000000, max_uses: 5, current_uses: 2, expires_at: 1700003600, created_by: 'u1' },
      { id: 'i2', invite_code: 'CODE2', created_at: 1, max_uses: null, current_uses: 0, expires_at: null, created_by: undefined },
    ]);
  });

  it('revokes with DELETE /invites/<id>', async () => {
    const api = new AccordApi('https://relay.test');
    mockFetch.mockResolvedValueOnce(jsonResponse(200, { status: 'revoked', invite_id: 'inv-42' }));
    await api.revokeInvite('inv-42', 'tok');
    expect(mockFetch.mock.calls[0][0]).toBe('https://relay.test/invites/inv-42');
    expect((mockFetch.mock.calls[0][1] as RequestInit).method).toBe('DELETE');
  });
});

// ── Reasons and messages ─────────────────────────────────────────────────

/** SPEC-01 section 8, desktop column. */
const SECTION_8: Record<string, string> = {
  invite_invalid: 'This invite link is invalid or was revoked',
  invite_expired: 'This invite has expired',
  invite_exhausted: 'This invite has reached its use limit',
  banned: "You can't join this node",
  device_banned: "You can't join this node",
  fingerprint_required: 'This node needs a device check. Update Accord and try again.',
  device_limit: 'Too many accounts from this device have joined this node',
  build_not_allowed: 'This node only accepts specific app builds',
  invite_required: 'This node requires an invite link',
  join_requests_full: "This node isn't accepting requests right now",
  unavailable: 'The server is busy. Try again.',
};

describe('T-43 reason messages', () => {
  it('maps every join refusal reason to its section 8 message', () => {
    for (const [reason, message] of Object.entries(SECTION_8)) {
      expect(joinErrorMessage(new ApiError('relay text', 403, reason))).toBe(message);
    }
    expect(joinErrorMessage(new ApiError('Rate limit exceeded', 429, 'rate_limited', 42))).toBe(
      'Too many attempts. Try again in 42 seconds.',
    );
    // A WS join_failed frame has the same fields.
    expect(joinErrorMessage({ type: 'join_failed', reason: 'rate_limited', retry_after: 7, error: 'x' })).toBe(
      'Too many attempts. Try again in 7 seconds.',
    );
    expect(admissionMessage('pending_approval')).toBe('Request sent. A moderator must approve it.');
    expect(admissionMessage('join_request_denied')).toBe('Your request to join was not approved');
  });

  it('falls back to the relay error text for unknown or missing reasons', () => {
    expect(joinErrorMessage(new ApiError('Invalid invite code', 400))).toBe('Invalid invite code');
    expect(joinErrorMessage(new ApiError('Something new', 400, 'some_future_reason'))).toBe('Something new');
  });

  it('keeps Join available only when the preview says nothing about the invite', () => {
    expect(isPreviewUnavailable(new ApiError('Rate limit exceeded', 429, 'rate_limited', 30))).toBe(true);
    expect(isPreviewUnavailable(new TypeError('Failed to fetch'))).toBe(true);
    expect(isPreviewUnavailable(new ApiError('Invalid invite code', 404, 'invite_invalid'))).toBe(false);
    expect(isPreviewUnavailable(new ApiError('Invite has expired', 410, 'invite_expired'))).toBe(false);
  });
});

// ── Redemption ───────────────────────────────────────────────────────────

describe('T-43 invite redemption', () => {
  const NODE = '6f1c2b8e-3d4a-4f5b-9c6d-7e8f9a0b1c2d';

  it('learns the node id from the preview and sends the node-scoped fingerprint', async () => {
    const api = new AccordApi('https://relay.test');
    api.setToken('tok');
    mockFetch
      .mockResolvedValueOnce(jsonResponse(200, { node_name: 'N', node_id: NODE, member_count: 3, server_build_hash: 'h' }))
      .mockResolvedValueOnce(jsonResponse(200, { status: 'joined', node_id: NODE, node_name: 'N' }));
    const outcome = await redeemInvite(api, 'Ab3dEf6hIj9kLm2nOp5qRs', 'tok');
    expect(outcome).toEqual({ status: 'joined', nodeId: NODE, nodeName: 'N' });
    expect(mockFetch.mock.calls[0][0]).toBe('https://relay.test/invites/Ab3dEf6hIj9kLm2nOp5qRs/preview');
    expect(mockFetch.mock.calls[1][0]).toBe('https://relay.test/invites/Ab3dEf6hIj9kLm2nOp5qRs/join');
    const sent = lastBody();
    expect(sent).toEqual({ device_fingerprint_hash: await nodeDeviceFingerprint(NODE) });
    expect(sent.device_fingerprint_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('redeems without a fingerprint when the preview fails', async () => {
    const api = new AccordApi('https://relay.test');
    mockFetch
      .mockResolvedValueOnce(jsonResponse(429, { error: 'Rate limit exceeded', code: 429, reason: 'rate_limited', retry_after: 9 }))
      .mockResolvedValueOnce(jsonResponse(200, { status: 'joined', node_id: NODE, node_name: 'N' }));
    const outcome = await redeemInvite(api, 'ABCDEFGH', 'tok');
    expect(outcome.status).toBe('joined');
    expect(lastBody()).toBeUndefined();
  });

  it('treats already_member as success and rethrows every other refusal with its reason', async () => {
    const api = new AccordApi('https://relay.test');
    mockFetch.mockResolvedValueOnce(
      jsonResponse(409, { error: 'Already a member of this node', code: 409, reason: 'already_member' }),
    );
    expect(await redeemInvite(api, 'ABCDEFGH', 'tok', { nodeId: NODE })).toEqual({
      status: 'already_member',
      nodeId: NODE,
    });

    mockFetch.mockResolvedValueOnce(
      jsonResponse(410, { error: 'Invite has expired', code: 410, reason: 'invite_expired' }),
    );
    const err = await redeemInvite(api, 'ABCDEFGH', 'tok', { nodeId: NODE }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(410);
    expect(err.reason).toBe('invite_expired');
    expect(err.message).toBe('Invite has expired');
    expect(joinErrorMessage(err)).toBe('This invite has expired');
  });

  it("treats a legacy relay's reason-less re-join answer as already_member (section 7.2)", async () => {
    const api = new AccordApi('https://relay.test');
    // A relay without admission/1 answers a re-join with 400 and no `reason`.
    mockFetch.mockResolvedValueOnce(jsonResponse(400, { error: 'Already a member of this node', code: 400 }));
    expect(await redeemInvite(api, 'ABCDEFGH', 'tok', { nodeId: NODE })).toEqual({
      status: 'already_member',
      nodeId: NODE,
    });
    expect(isAlreadyMember(new ApiError('Already a member of this node', 400))).toBe(true);

    // Any other reason-less legacy refusal is still an error.
    mockFetch.mockResolvedValueOnce(jsonResponse(400, { error: 'Invalid invite code', code: 400 }));
    const err = await redeemInvite(api, 'ABCDEFGH', 'tok', { nodeId: NODE }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(joinErrorMessage(err)).toBe('Invalid invite code');
    // A new relay's reason wins over the text.
    expect(isAlreadyMember(new ApiError('Already a member of this node', 403, 'banned'))).toBe(false);
  });

  it('shows the section 8 message in the join dialog (NodeDiscovery)', async () => {
    mockFetch.mockImplementation(async (url: string) =>
      url.endsWith('/preview')
        ? jsonResponse(404, { error: 'Invalid invite code', code: 404, reason: 'invite_invalid' })
        : jsonResponse(404, { error: 'Invalid invite code', code: 404, reason: 'invite_invalid' }),
    );
    const onNodeJoined = vi.fn();
    render(<JoinNodeDialog isOpen onClose={() => {}} onNodeJoined={onNodeJoined} token="tok" />);
    fireEvent.change(screen.getByPlaceholderText('Enter invite code...'), { target: { value: 'ABCDEFGH' } });
    fireEvent.click(screen.getByText('Join Node'));
    await waitFor(() =>
      expect(screen.getByText('This invite link is invalid or was revoked')).toBeInTheDocument(),
    );
    expect(onNodeJoined).not.toHaveBeenCalled();
  });
});

// ── Node settings: invite form, kick and leave ───────────────────────────

describe('T-43 node settings (section 8: invite default, kick, leave)', () => {
  const SETTINGS_NODE: Node = { id: 'n1', name: 'Node', owner_id: 'owner', created_at: 0 };
  const BOB = {
    user_id: 'u2',
    display_name: 'Bob',
    roles: [],
    online: false,
    status: 'offline',
    joined_at: 0,
    node_role: 'member',
  };

  type Route = (url: string, init: RequestInit) => ReturnType<typeof jsonResponse> | undefined;

  /** Serve the relay from `route`; anything it leaves out gets an empty 200. */
  function serve(route: Route) {
    mockFetch.mockImplementation(async (url: string, init: RequestInit = {}) => {
      const answer = route(url, init);
      if (answer) return answer;
      if (url.endsWith('/members/batch')) return jsonResponse(200, { members: [BOB], roles: [] });
      if (url.endsWith('/roles')) return jsonResponse(200, { roles: [] });
      if (url.endsWith('/invites') && (init.method ?? 'GET') === 'GET') return jsonResponse(200, { invites: [] });
      return jsonResponse(200, {});
    });
  }

  function callsTo(suffix: string, method = 'GET') {
    return mockFetch.mock.calls.filter(
      ([url, init]) => String(url).endsWith(suffix) && ((init as RequestInit | undefined)?.method ?? 'GET') === method,
    );
  }

  /** The parsed body of the n-th invite creation (undefined when none was sent). */
  function createBody(n: number): any {
    const init = callsTo('/nodes/n1/invites', 'POST')[n][1] as RequestInit;
    return init.body === undefined ? undefined : JSON.parse(init.body as string);
  }

  function renderSettings(props: Partial<Parameters<typeof NodeSettings>[0]> = {}) {
    sharedApi.setBaseUrl('https://relay.test');
    return render(
      <NodeSettings
        isOpen
        onClose={() => {}}
        node={SETTINGS_NODE}
        token="tok"
        userRole="admin"
        relayFeatures={[ADMISSION_FEATURE]}
        {...props}
      />,
    );
  }

  async function openCreateInvite() {
    fireEvent.click(screen.getByText('Invites'));
    await waitFor(() => expect(screen.getByText('No active invites')).toBeInTheDocument());
    fireEvent.click(screen.getByText(/Create Invite/));
  }

  it('creates 24-hour invites by default; "Never" is an explicit choice (OD-17)', async () => {
    serve((url, init) =>
      url.endsWith('/nodes/n1/invites') && init.method === 'POST'
        ? jsonResponse(200, { invite_code: 'X', expires_at: 1 })
        : undefined,
    );
    renderSettings();
    await openCreateInvite();
    fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(callsTo('/nodes/n1/invites', 'POST')).toHaveLength(1));
    expect(createBody(0)).toEqual({ expires_in_seconds: 86400 });
    await screen.findByText('Invite created successfully!');

    // After a create the form is back at 24 hours; "Never" sends no expiry.
    await openCreateInvite();
    expect(screen.getByLabelText('Expires in (hours)')).toHaveValue(24);
    fireEvent.click(screen.getByLabelText('Never expires'));
    expect(screen.getByLabelText('Expires in (hours)')).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(callsTo('/nodes/n1/invites', 'POST')).toHaveLength(2));
    expect(createBody(1)).toBeUndefined();
  });

  it('sends the 24-hour default as whole hours to a legacy relay, and refuses an empty lifetime', async () => {
    serve((url, init) =>
      url.endsWith('/nodes/n1/invites') && init.method === 'POST' ? jsonResponse(200, { invite_code: 'X' }) : undefined,
    );
    renderSettings({ relayFeatures: [] });
    await openCreateInvite();
    // Clearing the field does not mean "never".
    fireEvent.change(screen.getByLabelText('Expires in (hours)'), { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('Enter how many hours the invite lasts, or choose Never')).toBeInTheDocument();
    expect(callsTo('/nodes/n1/invites', 'POST')).toHaveLength(0);

    fireEvent.change(screen.getByLabelText('Expires in (hours)'), { target: { value: '24' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(callsTo('/nodes/n1/invites', 'POST')).toHaveLength(1));
    expect(createBody(0)).toEqual({ expires_in_hours: 24 });
  });

  it('a kick answered with not_member reloads the member list and shows no error', async () => {
    serve((url, init) =>
      url.endsWith('/nodes/n1/members/u2') && init.method === 'DELETE'
        ? jsonResponse(404, { error: 'User is not a member of this node', code: 404, reason: 'not_member' })
        : undefined,
    );
    renderSettings();
    fireEvent.click(screen.getByText('Members'));
    await screen.findByText('Bob');
    expect(callsTo('/members/batch')).toHaveLength(1);

    fireEvent.click(screen.getByRole('button', { name: 'Kick' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm Kick' }));
    await waitFor(() => expect(callsTo('/members/batch')).toHaveLength(2));
    expect(callsTo('/nodes/n1/members/u2', 'DELETE')).toHaveLength(1);
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Confirm Kick' })).not.toBeInTheDocument());
    expect(screen.queryByText('User is not a member of this node')).not.toBeInTheDocument();
  });

  it('a rate-limited kick shows the section 8 retry message', async () => {
    serve((url, init) =>
      url.endsWith('/nodes/n1/members/u2') && init.method === 'DELETE'
        ? jsonResponse(429, { error: 'Rate limit exceeded', code: 429, reason: 'rate_limited', retry_after: 12 })
        : undefined,
    );
    renderSettings();
    fireEvent.click(screen.getByText('Members'));
    await screen.findByText('Bob');
    fireEvent.click(screen.getByRole('button', { name: 'Kick' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm Kick' }));
    expect(await screen.findByText('Too many attempts. Try again in 12 seconds.')).toBeInTheDocument();
    expect(screen.queryByText('Rate limit exceeded')).not.toBeInTheDocument();
  });

  it('maps owner_cannot_leave and rate_limited on leave to the section 8 messages', async () => {
    vi.stubGlobal('confirm', () => true);
    const leaveAnswers = [
      jsonResponse(400, { error: 'Owner cannot leave', code: 400, reason: 'owner_cannot_leave' }),
      jsonResponse(429, { error: 'Rate limit exceeded', code: 429, reason: 'rate_limited', retry_after: 5 }),
    ];
    serve((url, init) =>
      url.endsWith('/nodes/n1/leave') && init.method === 'POST' ? leaveAnswers.shift() : undefined,
    );
    const onLeaveNode = vi.fn();
    renderSettings({ userRole: 'member', onLeaveNode });
    fireEvent.click(screen.getByRole('button', { name: 'Leave Node' }));
    expect(await screen.findByText('Transfer or delete the node instead')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Leave Node' }));
    expect(await screen.findByText('Too many attempts. Try again in 5 seconds.')).toBeInTheDocument();
    expect(onLeaveNode).not.toHaveBeenCalled();
  });
});

/** Every source file of the frontend, without tests. */
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name !== '__tests__' && name !== 'node_modules') out.push(...sourceFiles(path));
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name)) {
      out.push(path);
    }
  }
  return out;
}

// Vitest runs from desktop/frontend (the jsdom environment gives
// import.meta.url a non-file scheme).
const SRC = join(process.cwd(), 'src') + '/';

describe('T-43 redemption call sites', () => {
  it('every invite redemption goes through redeemInvite and maps reasons', () => {
    for (const file of ['App.tsx', 'components/ChatArea.tsx', 'NodeDiscovery.tsx']) {
      const text = readFileSync(join(SRC, file), 'utf8');
      // No call site redeems an invite directly any more.
      expect(text, file).not.toMatch(/\.joinNodeByInvite\(/);
      expect(text, file).toMatch(/redeemInvite\(/);
      expect(text, file).toMatch(/joinErrorMessage\(/);
    }
    // App.tsx has five redemption call sites (SPEC-01 REQ-43).
    const app = readFileSync(join(SRC, 'App.tsx'), 'utf8');
    expect(app.match(/redeemInvite\(/g)?.length).toBe(5);
  });
});

// ── node_joined, features and the socket ─────────────────────────────────

class FakeWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  static sockets: FakeWebSocket[] = [];
  readyState = 0;
  sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: ((event: { code: number }) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  constructor(public url: string) {
    FakeWebSocket.sockets.push(this);
  }
  send(data: string) {
    this.sent.push(data);
  }
  close() {}
  deliver(frame: unknown) {
    this.onmessage?.({ data: JSON.stringify(frame) });
  }
}

function connectedSocket(): { socket: AccordWebSocket; fake: FakeWebSocket } {
  FakeWebSocket.sockets = [];
  vi.stubGlobal('WebSocket', FakeWebSocket);
  const socket = new AccordWebSocket('tok', 'http://relay.test');
  socket.connect();
  const fake = FakeWebSocket.sockets[0];
  fake.readyState = FakeWebSocket.OPEN;
  fake.onopen?.();
  fake.deliver({ type: 'authenticated', user_id: 'me' });
  return { socket, fake };
}

describe('T-43 node_joined and the relay features record', () => {
  it('a forged node_joined only reloads the node list; nothing is sent', () => {
    const { socket, fake } = connectedSocket();
    const reloadNodes = vi.fn();
    const onNotice = vi.fn();
    registerAdmissionHandlers(socket, { reloadNodes, onNotice });
    const sentBefore = fake.sent.length;

    fake.deliver({ type: 'node_joined', node_id: 'n-forged', node_name: 'Forged' });

    expect(reloadNodes).toHaveBeenCalledTimes(1);
    expect(fake.sent.length).toBe(sentBefore);
    expect(fake.sent.some((m) => m.includes('StoreSenderKey'))).toBe(false);
    expect(onNotice).not.toHaveBeenCalled();

    fake.deliver({ type: 'join_request_denied', node_id: 'n1' });
    expect(onNotice).toHaveBeenCalledWith('Your request to join was not approved');
    expect(fake.sent.length).toBe(sentBefore);
    socket.disconnect();
  });

  it('no other node_joined listener exists in the desktop', () => {
    const listeners = sourceFiles(SRC).filter((file) =>
      /\.on\(\s*['"]node_joined['"]/.test(readFileSync(file, 'utf8')),
    );
    expect(listeners.map((f) => f.slice(SRC.length))).toEqual(['admission.ts']);
  });

  it('remembers the features of hello and forgets them on disconnect', () => {
    const { socket, fake } = connectedSocket();
    expect(socket.relayFeatures()).toEqual([]);
    fake.deliver({ type: 'hello', server_version: '0.1.0', features: ['admission/1', 'screen/1', 7] });
    expect(socket.relayFeatures()).toEqual(['admission/1', 'screen/1']);
    fake.onclose?.({ code: 1000 });
    expect(socket.relayFeatures()).toEqual([]);
    socket.disconnect();
  });

  it('JoinNode carries the optional invite and fingerprint fields', () => {
    const { socket, fake } = connectedSocket();
    socket.joinNode('n1');
    socket.joinNode('n1', { inviteCode: 'ABCDEFGH', deviceFingerprintHash: 'a'.repeat(64) });
    const frames = fake.sent.slice(-2).map((m) => JSON.parse(m).message_type);
    expect(frames[0]).toEqual({ JoinNode: { node_id: 'n1' } });
    expect(frames[1]).toEqual({
      JoinNode: { node_id: 'n1', invite_code: 'ABCDEFGH', device_fingerprint_hash: 'a'.repeat(64) },
    });
    socket.disconnect();
  });
});

// ── Node-scoped device fingerprint (section 6.9) ─────────────────────────

describe('T-43 node-scoped device fingerprint', () => {
  const SECRET = Uint8Array.from({ length: 32 }, (_, i) => i);
  const NODE_A = '00000000-0000-4000-8000-00000000000a';
  const NODE_B = '00000000-0000-4000-8000-00000000000b';

  function reference(secret: Uint8Array, nodeId: string): string {
    return createHmac('sha256', Buffer.from(secret))
      .update(`accord-node-device-v1:${nodeId}`, 'utf8')
      .digest('hex');
  }

  it('matches an independently computed HMAC-SHA-256 and differs per node', () => {
    expect(NODE_FINGERPRINT_LABEL).toBe('accord-node-device-v1:');
    const a = computeNodeFingerprint(SECRET, NODE_A);
    const b = computeNodeFingerprint(SECRET, NODE_B);
    expect(a).toBe(reference(SECRET, NODE_A));
    expect(b).toBe(reference(SECRET, NODE_B));
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toBe(b);
    // The node id is used in its lowercase form.
    expect(computeNodeFingerprint(SECRET, NODE_A.toUpperCase())).toBe(a);
  });

  it('keeps one 32-byte install secret per installation in accord_install_secret', async () => {
    expect(INSTALL_SECRET_KEY).toBe('accord_install_secret');
    const first = getInstallSecret();
    expect(first).not.toBeNull();
    expect(first!.length).toBe(32);
    const stored = localStorage.getItem(INSTALL_SECRET_KEY)!;
    expect(atob(stored).length).toBe(32);
    expect(Array.from(getInstallSecret()!)).toEqual(Array.from(first!));
    expect(await nodeDeviceFingerprint(NODE_A)).toBe(reference(first!, NODE_A));
  });
});
