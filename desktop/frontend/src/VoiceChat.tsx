/**
 * VoiceChat — the voice panel of a call. Every call is relay mode (SPEC-03
 * REQ-41): audio goes through the relay end to end encrypted, under keys that
 * each participant sends only to the participants its panel lists, inside
 * pairwise Double Ratchet sessions (`voice/relay.ts`, `voice/callKeys.ts`).
 * Until SPEC-05 and SPEC-06 land, the relay's member list decides who those
 * participants are, so the panel says "not verified" (REQ-9).
 *
 * The panel shows the call security indicator (§8.1) and, for every
 * participant, its state, short id, key mark and notes (§8.2, REQ-11),
 * computed only from local key state, eligibility and timers (REQ-31), plus
 * a warning when two participants share a display name. There is no mode
 * badge and no mode toggle: a relay report of P2P only shows a note
 * (REQ-41), and this client contains no peer-connection code (REQ-39).
 *
 * Screen sharing (A1, §8.4) is end to end encrypted over the relay, to the
 * same participants as the audio. The Share Screen control shows why it is
 * unavailable where it is (no `screen/1` on the relay, a failed probe, the
 * macOS app, which can only view); while sharing, the panel says how many
 * participants can see the screen. Each share in the call gets a tile with
 * opt-in Watch; pictures come only from fragments that authenticated and
 * were validated, drawn into a canvas (REQ-48, REQ-49).
 */

import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useAppContext } from './components/AppContext';
import { Icon } from './components/Icon';
import type { VoiceChannelUser } from './hooks/useVoice';
import { AccordWebSocket } from './ws';
import { RelayVoiceConnection, type RelayVoiceTimings, type VoiceConnectionState } from './voice/relay';
import { AudioManager } from './voice/audio';
import { MicrophoneCapture, WebAudioPlayback, type VoiceMediaInput, type VoiceMediaOutput } from './voice/mediaIo';
import { shortIdOf, type CallClock, type CallKeyBridge } from './voice/callKeyBridge';
import {
  INDICATOR_TEXT,
  PARTICIPANT_LABEL_TEXT,
  type CallKeyTimings,
  type ParticipantView,
} from './voice/callKeys';
import type { RemoteTileView, ScreenState } from './voice/relay';
import {
  canvasSurface,
  screenNoticeText,
  shareControlText,
  viewerTileText,
  watchRejectedText,
  type ScreenPlatform,
} from './voice/screenShare';
import { WATCH_MAX } from './voice/screenFrame';
import { duplicateNameKeys, memberDisplayName, nameKey } from './voice/displayNames';

/**
 * Test seam (SPEC-03 §10.1, F tests): the media input and output, the clock
 * and test timings of the call. The app passes none of them.
 */
export interface VoiceCallEnvironment {
  input?: VoiceMediaInput;
  output?: VoiceMediaOutput;
  clock?: CallClock;
  callTimings?: Partial<CallKeyTimings>;
  voiceTimings?: Partial<RelayVoiceTimings>;
  /** Screen capture, codecs and renderer; the browser's by default. */
  screen?: ScreenPlatform;
  /** Called with each connection the panel builds. */
  onConnection?: (conn: RelayVoiceConnection) => void;
}

interface VoiceChatProps {
  ws: AccordWebSocket | null;
  currentUserId: string | null;
  channelId: string;
  channelName: string;
  onLeave: () => void;
  /** SPEC-03 REQ-9: N, the node recorded with the channel when the user selected it. */
  nodeId?: string | null;
  /** SPEC-03 §6.10: the E2EE bridge for `CallKeyManager`. */
  bridge?: CallKeyBridge | null;
  /** Tests only. */
  callEnv?: VoiceCallEnvironment;
}

/** §8.3: the non-modal note while the latest relay report for the channel says P2P (REQ-41). */
export const RELAY_P2P_NOTE =
  "Someone using an older version of Accord switched this channel to P2P. This app always uses encrypted relay mode, so people on older versions can't hear you or see your screen.";

/** §8.4, row 1: the Source B note (§6.13.3). */
export const SCREEN_SOURCE_B_NOTE = 'Sharing may pause while Accord is minimized or hidden.';

/** The Linux addition to "Couldn't capture your screen" (§8.4). */
function isLinuxDesktop(): boolean {
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent ?? '' : '';
  return /Linux/.test(ua) && !/Android/.test(ua);
}

/** OD-52: no hard cap, but a warning above 25 participants. */
export const LARGE_CALL_THRESHOLD = 25;

const PHASE_TEXT: Record<VoiceConnectionState['phase'], string> = {
  connecting: 'Joining voice…',
  joined: 'Voice connected',
  reconnecting: 'Reconnecting secure voice…',
  unavailable: 'Secure voice unavailable; sign in again',
  failed: "Couldn't join voice",
  removed: 'You were removed from the voice channel',
  left: 'Disconnected',
};

export const VoiceChat: React.FC<VoiceChatProps> = ({
  ws,
  currentUserId,
  channelId,
  channelName,
  onLeave,
  nodeId,
  bridge,
  callEnv,
}) => {
  const ctx = useAppContext();
  const isMuted = ctx.voiceMuted;
  const setIsMuted = ctx.setVoiceMuted;
  const isDeafened = ctx.voiceDeafened;
  const setIsDeafened = ctx.setVoiceDeafened;
  const [outputVolume, setOutputVolume] = useState(100);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [speakingPeers, setSpeakingPeers] = useState<ReadonlySet<string>>(new Set());
  const [voiceState, setVoiceState] = useState<VoiceConnectionState | null>(null);
  const [showDetails, setShowDetails] = useState(false);
  const [showAudience, setShowAudience] = useState(false);

  const voiceConnRef = useRef<RelayVoiceConnection | null>(null);
  const audioManagerRef = useRef<AudioManager | null>(null);
  // REQ-5: the mute and deafen state at the moment a connection is built.
  const mutedRef = useRef(isMuted);
  const deafenedRef = useRef(isDeafened);
  mutedRef.current = isMuted;
  deafenedRef.current = isDeafened;
  const callEnvRef = useRef(callEnv);
  callEnvRef.current = callEnv;

  // One connection per voice session; a channel switch builds a new one.
  // Relay mode reports never rebuild it (REQ-41).
  useEffect(() => {
    if (!ws || !currentUserId) return;

    const audioManager = new AudioManager();
    audioManagerRef.current = audioManager;
    const env = callEnvRef.current;
    const conn = new RelayVoiceConnection({
      ws,
      channelId,
      nodeId: nodeId ?? null,
      bridge: bridge ?? null,
      muted: mutedRef.current,
      deafened: deafenedRef.current,
      input: env?.input ?? new MicrophoneCapture(),
      output: env?.output ?? new WebAudioPlayback(audioManager),
      clock: env?.clock,
      callTimings: env?.callTimings,
      voiceTimings: env?.voiceTimings,
      screen: env?.screen,
    });
    voiceConnRef.current = conn;
    env?.onConnection?.(conn);
    conn.onStateChange = state => setVoiceState(state);
    conn.onSpeaking = (_userId, speaking) => setIsSpeaking(speaking);
    setVoiceState(conn.state);

    // Speaking flags are relay-asserted plaintext (OD-56): they light the
    // speaking ring and never change a security state (REQ-31).
    const self = currentUserId.toLowerCase();
    const onSpeakingState = (data: any) => {
      if (!data || typeof data.user_id !== 'string' || typeof data.channel_id !== 'string') return;
      if (data.channel_id.toLowerCase() !== channelId.toLowerCase()) return;
      const user = data.user_id.toLowerCase();
      if (user === self) return;
      setSpeakingPeers(prev => {
        const next = new Set(prev);
        if (data.speaking === true) next.add(user);
        else next.delete(user);
        return next;
      });
    };
    ws.on('voice_speaking_state', onSpeakingState);

    // Arm the native microphone permission gate before capture: the desktop
    // shell allows capture only during a call. No-op on the web.
    const setVoiceArmed = (armed: boolean) => {
      try {
        (window as any).__TAURI__?.core?.invoke('set_voice_capture_armed', { armed });
      } catch { /* web build: no native gate */ }
    };
    setVoiceArmed(true);

    conn.connect().catch(() => setVoiceState(conn.state));

    return () => {
      setVoiceArmed(false);
      ws.off('voice_speaking_state', onSpeakingState);
      conn.onStateChange = null;
      conn.onSpeaking = null;
      conn.disconnect();
      audioManager.destroy();
      voiceConnRef.current = null;
      audioManagerRef.current = null;
      setSpeakingPeers(new Set());
      setIsSpeaking(false);
    };
  }, [ws, channelId, currentUserId, nodeId, bridge]);

  // Sync mute state
  useEffect(() => {
    voiceConnRef.current?.setMuted(isMuted);
  }, [isMuted]);

  // Sync deafen state
  useEffect(() => {
    voiceConnRef.current?.setDeafened(isDeafened);
    if (isDeafened) setIsMuted(true);
  }, [isDeafened]);

  // Sync volume
  useEffect(() => {
    audioManagerRef.current?.setMasterVolume(outputVolume / 100);
  }, [outputVolume]);

  const toggleMute = useCallback(() => {
    audioManagerRef.current?.resume();
    setIsMuted(prev => !prev);
  }, []);

  const toggleDeafen = useCallback(() => {
    audioManagerRef.current?.resume();
    setIsDeafened(prev => !prev);
  }, []);

  const handleDisconnect = useCallback(() => {
    voiceConnRef.current?.disconnect();
    onLeave();
  }, [onLeave]);

  // REQ-43: the click handler's first action is the connection's synchronous
  // call into getDisplayMedia; nothing is awaited before it.
  const handleScreenControl = useCallback(() => {
    const conn = voiceConnRef.current;
    if (!conn) return;
    const kind = conn.screenControl().kind;
    if (kind === 'idle') conn.startScreenShare();
    else if (kind === 'sharing' || kind === 'starting') conn.stopScreenShare();
  }, []);

  const participants: readonly ParticipantView[] = voiceState?.call?.participants ?? [];

  // Relay-supplied display names (C014): shown with the short id, and marked
  // when two users in V and the local user share one (REQ-11).
  const selfName = ctx.appState.user?.display_name || 'You';
  const nameOf = useCallback((userId: string, shortId: string): string => memberDisplayName(ctx.members, userId, shortId), [ctx.members]);
  const names = useMemo(() => {
    const map = new Map<string, string>();
    for (const p of participants) map.set(p.userId, nameOf(p.userId, p.shortId));
    return map;
  }, [participants, nameOf]);
  const duplicateNames = useMemo(() => duplicateNameKeys([selfName, ...names.values()]), [names, selfName]);
  const isDuplicate = (name: string) => duplicateNames.has(nameKey(name));

  // Sync voice channel users to app context for sidebar display. The panel
  // re-renders on every state change of the connection (a new participants
  // array each time), so the app is updated only when the list's content
  // changes: an equal list must not re-render the whole app.
  const voiceUsers: VoiceChannelUser[] = [
    {
      userId: currentUserId || '',
      displayName: selfName,
      isSpeaking,
      isMuted,
    },
    ...participants.map(p => ({
      userId: p.userId,
      displayName: names.get(p.userId) ?? p.shortId,
      isSpeaking: speakingPeers.has(p.userId),
    })),
  ];
  const voiceUsersKey = JSON.stringify(voiceUsers);
  const voiceUsersRef = useRef(voiceUsers);
  voiceUsersRef.current = voiceUsers;
  useEffect(() => {
    ctx.setVoiceChannelUsers(voiceUsersRef.current);
  }, [voiceUsersKey]);

  // Clear users on unmount
  useEffect(() => {
    return () => { ctx.setVoiceChannelUsers([]); };
  }, []);

  const phase = voiceState?.phase ?? 'connecting';
  const statusText = voiceState?.reconnecting ? PHASE_TEXT.reconnecting : PHASE_TEXT[phase];
  const statusClass = phase === 'joined' ? 'connected' : phase === 'unavailable' || phase === 'failed' || phase === 'removed' ? 'error' : 'pending';
  const indicator = phase === 'unavailable'
    ? 'unavailable'
    : phase === 'joined' && voiceState?.call ? voiceState.call.indicator : null;
  const indicatorText = indicator ? INDICATOR_TEXT[indicator] : null;
  const ended = phase === 'removed' || phase === 'failed' || phase === 'unavailable';

  const screenState: ScreenState | null = voiceState?.screen ?? null;
  const control = screenState?.control ?? ({ row: 3, kind: 'not_ready' } as const);
  const controlText = shareControlText(control);
  const controlEnabled = control.kind === 'idle' || control.kind === 'sharing' || control.kind === 'starting';
  const controlLabel = control.kind === 'sharing' ? 'Stop Sharing' : control.kind === 'starting' ? 'Cancel' : 'Share Screen';
  const local = screenState?.local ?? null;
  const audience = control.kind === 'sharing' ? local?.audience ?? null : null;
  const audienceSize = audience?.members.length ?? 0;
  /** REQ-11's identity label of any user: display name and short id. */
  const labelOf = (userId: string): { name: string; shortId: string } => {
    const p = participants.find(x => x.userId === userId);
    const shortId = p?.shortId ?? shortIdOf(userId);
    return { name: names.get(userId) ?? nameOf(userId, shortId), shortId };
  };

  return (
    <div className="voice-panel" data-testid="voice-panel">
      {/* Header */}
      <div className="voice-panel-header">
        <div className="voice-panel-status">
          <span className={`voice-panel-status-label ${statusClass}`} role="status">
            {statusText}
          </span>
          <span className="voice-panel-channel">{channelName}</span>
          {indicatorText && (
            <button
              type="button"
              className={`voice-security-indicator indicator-${indicator}`}
              aria-expanded={showDetails}
              aria-controls="voice-security-details"
              onClick={() => setShowDetails(v => !v)}
              title="Who receives your call keys"
            >
              <Icon name="shield" size={12} />
              <span>{indicatorText}</span>
            </button>
          )}
        </div>
        <button onClick={handleDisconnect} className="voice-panel-disconnect">
          {ended ? 'Close' : 'Disconnect'}
        </button>
      </div>

      {/* Notes */}
      {(voiceState?.relayReportsP2p || voiceState?.listenOnly || participants.length + 1 > LARGE_CALL_THRESHOLD) && (
        <div className="voice-panel-notes">
          {voiceState?.relayReportsP2p && (
            <p className="voice-note voice-note-relay-mode" role="note">{RELAY_P2P_NOTE}</p>
          )}
          {voiceState?.listenOnly && (
            <p className="voice-note" role="note">Microphone unavailable: you joined listen-only.</p>
          )}
          {participants.length + 1 > LARGE_CALL_THRESHOLD && (
            <p className="voice-note" role="note">
              Large call: above {LARGE_CALL_THRESHOLD} participants, encryption keys take longer to reach everyone.
            </p>
          )}
        </div>
      )}

      {/* Indicator details (§8.1: every participant with its state and short id) */}
      {showDetails && indicatorText && (
        <div className="voice-security-details" id="voice-security-details">
          <p className="voice-security-explainer">
            {indicator === 'e2ee_verified'
              ? 'Your audio is encrypted for the participants marked with a key. Their identities are verified.'
              : "Your audio is encrypted for the participants marked with a key. Who is a member comes from the relay's member list, and identities are not verified."}
          </p>
          {participants.length === 0 ? (
            <p className="voice-security-explainer">No one else is in the call.</p>
          ) : (
            <ul className="voice-security-list">
              {participants.map(p => (
                <li key={p.userId}>
                  <span>{names.get(p.userId)}</span>{' '}
                  <code>{p.shortId}</code>{' '}
                  <span>{PARTICIPANT_LABEL_TEXT[p.label]}</span>
                  {p.recipient ? <span className="voice-key-mark-text"> · receives your key</span> : null}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* Body */}
      <div className="voice-panel-body">
        {/* Users */}
        <div className="voice-panel-users">
          <span className="voice-panel-users-label">
            Users ({participants.length + 1}):
          </span>

          <ParticipantPill
            label={selfName === 'You' ? 'You' : `${selfName} (you)`}
            isSpeaking={isSpeaking}
            isMuted={isMuted}
            duplicate={isDuplicate(selfName)}
          />

          {participants.map(p => (
            <ParticipantPill
              key={p.userId}
              userId={p.userId}
              label={names.get(p.userId) ?? p.shortId}
              shortId={p.shortId}
              state={PARTICIPANT_LABEL_TEXT[p.label]}
              stateClass={p.label}
              recipient={p.recipient}
              isSpeaking={speakingPeers.has(p.userId)}
              duplicate={isDuplicate(names.get(p.userId) ?? p.shortId)}
              notes={[
                ...(p.notes.sessionProblem ? ['Secure session problem'] : []),
                ...(p.notes.outdatedApp ? ['May be using an outdated app'] : []),
                ...(p.notes.olderAppP2p ? ['May be using an older app in P2P mode'] : []),
                ...(p.notes.audioUnverifiable ? [`Audio from ${names.get(p.userId) ?? p.shortId} can't be verified`] : []),
              ]}
            />
          ))}
        </div>

        {/* Controls */}
        <div className="voice-panel-controls">
          <button
            onClick={toggleMute}
            className={`voice-ctrl-round ${isMuted ? 'muted' : 'active'}`}
            title={isMuted ? 'Unmute' : 'Mute'}
          >
            <Icon name={isMuted ? 'mic-off' : 'mic'} size={16} />
          </button>

          <button
            onClick={toggleDeafen}
            className={`voice-ctrl-round ${isDeafened ? 'muted' : 'neutral'}`}
            title={isDeafened ? 'Undeafen' : 'Deafen'}
          >
            <Icon name={isDeafened ? 'speaker-off' : 'speaker'} size={16} />
          </button>

          {/* §8.4: the Share Screen control. Its state is also visible text
              below the controls, since a disabled button's tooltip is not
              shown everywhere. No other transport is ever offered (REQ-42). */}
          <button
            type="button"
            className={`voice-ctrl-round ${control.kind === 'sharing' ? 'active' : 'neutral'} voice-screenshare-control state-${control.kind}`}
            disabled={!controlEnabled}
            aria-label={controlLabel}
            aria-describedby="voice-screenshare-status"
            title={controlText}
            data-testid="screen-share-control"
            onClick={handleScreenControl}
          >
            <Icon name="screen-share" size={16} />
          </button>

          <div className="voice-volume-control">
            <span className="voice-volume-label">Vol</span>
            <input
              type="range" min="0" max="100"
              value={outputVolume}
              onChange={(e) => setOutputVolume(parseInt(e.target.value))}
              className="voice-volume-slider"
            />
            <span className="voice-volume-value">{outputVolume}%</span>
          </div>
        </div>
      </div>

      {/* Screen sharing (§8.4) */}
      <div className="voice-screen" data-testid="voice-screen">
        <p className="voice-screenshare-status" id="voice-screenshare-status">
          <span className="voice-screenshare-state" data-testid="screen-share-state">{controlText}</span>
        </p>

        {control.kind === 'sharing' && (
          <div className="voice-screen-sharing" data-testid="screen-sharing-status">
            <button
              type="button"
              className="voice-screen-audience"
              aria-expanded={showAudience}
              aria-controls="voice-screen-audience-list"
              onClick={() => setShowAudience(v => !v)}
              title="Who can see your screen"
            >
              {audienceSize === 0
                ? 'No one else can see your screen yet'
                : `Your screen can be seen by ${audienceSize} ${audienceSize === 1 ? 'participant' : 'participants'}`}
              {audience && audienceSize > 0 ? ` (${audience.acknowledged} confirmed)` : ''}
            </button>
            {indicatorText && <span className="voice-screen-indicator">{indicatorText}</span>}
            <span className="voice-screen-watchers">{local?.watchers ?? 0} watching</span>
            {local?.source === 'video' && <span className="voice-note">{SCREEN_SOURCE_B_NOTE}</span>}
            {showAudience && (
              <ul className="voice-screen-audience-list" id="voice-screen-audience-list">
                {(audience?.members ?? []).map(id => {
                  const l = labelOf(id);
                  return (
                    <li key={id} data-user-id={id}>
                      <span>{l.name}</span> <code>{l.shortId}</code>
                      {isDuplicate(l.name) && <span className="voice-user-pill-dup"> Same name as another participant</span>}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        )}

        {screenState?.notice && (
          <p className="voice-note voice-screen-notice" role="note" data-testid="screen-notice">
            {screenNoticeText(screenState.notice, isLinuxDesktop())}
          </p>
        )}

        {local?.preview && (control.kind === 'sharing' || control.kind === 'starting') && <PreviewMount element={local.preview} />}

        {(screenState?.remote ?? []).map(t => {
          const l = labelOf(t.sharerId);
          return (
            <ScreenTile
              key={t.sharerId}
              tile={t}
              name={l.name}
              shortId={l.shortId}
              duplicate={isDuplicate(l.name)}
              indicatorText={indicatorText}
              watchLimitReached={(screenState?.watching ?? 0) >= WATCH_MAX}
              conn={voiceConnRef.current}
            />
          );
        })}
      </div>
    </div>
  );
};

/** The local preview (REQ-43): the captured track itself, in the DOM (Source B reads it). */
const PreviewMount: React.FC<{ element: HTMLVideoElement }> = ({ element }) => {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = host.current;
    if (!h) return;
    element.classList.add('voice-screen-preview-video');
    h.appendChild(element);
    return () => {
      if (element.parentNode === h) h.removeChild(element);
    };
  }, [element]);
  return <div className="voice-screen-preview" ref={host} data-testid="screen-preview" aria-label="Your shared screen" />;
};

/** One entry of the remote share list (§8.4 viewer tile). */
const ScreenTile: React.FC<{
  tile: RemoteTileView;
  name: string;
  shortId: string;
  duplicate: boolean;
  indicatorText: string | null;
  watchLimitReached: boolean;
  conn: RelayVoiceConnection | null;
}> = ({ tile, name, shortId, duplicate, indicatorText, watchLimitReached, conn }) => {
  const sharer = tile.sharerId;
  const canvasRef = useCallback((el: HTMLCanvasElement | null) => {
    conn?.attachScreenSurface(sharer, el ? canvasSurface(el) : null);
  }, [conn, sharer]);
  const state = tile.tile;
  const text = viewerTileText(state, name);
  return (
    <div
      className={`voice-screen-tile row-${state.row} ${state.kind}`}
      data-testid="screen-tile"
      data-sharer-id={sharer}
      data-row={state.row}
    >
      <div className="voice-screen-tile-header">
        <span className="voice-screen-tile-name">{name}</span>
        <code className="voice-user-pill-shortid">{shortId}</code>
        {duplicate && <span className="voice-user-pill-dup">Same name as another participant</span>}
        {indicatorText && <span className="voice-screen-tile-indicator">{indicatorText}</span>}
      </div>
      {tile.watching && (
        <canvas
          ref={canvasRef}
          className={`voice-screen-canvas${state.kind === 'stalled' ? ' dimmed' : ''}`}
          data-testid="screen-canvas"
        />
      )}
      {text && <p className="voice-screen-tile-status">{text}</p>}
      {state.kind === 'not_watching' && tile.cantDisplay && (
        <p className="voice-screen-tile-note">Video from {name} can't be displayed.</p>
      )}
      {state.kind === 'not_watching' && tile.rejected && (
        <p className="voice-screen-tile-note">{watchRejectedText(tile.rejected)}</p>
      )}
      {state.kind === 'not_watching' && (
        <>
          <button
            type="button"
            className="voice-screen-watch"
            disabled={!tile.canWatch}
            onClick={() => conn?.watchScreen(sharer)}
          >
            Watch
          </button>
          {watchLimitReached && <span className="voice-screen-tile-note">You're already watching 2 screens</span>}
        </>
      )}
      {tile.watching && (
        <button type="button" className="voice-screen-unwatch" onClick={() => conn?.unwatchScreen(sharer)}>
          Stop watching
        </button>
      )}
    </div>
  );
};

/** One participant: name, short id, state, key mark, notes and speaking ring (§8.2, REQ-11). */
const ParticipantPill: React.FC<{
  userId?: string;
  label: string;
  shortId?: string;
  state?: string;
  stateClass?: string;
  recipient?: boolean;
  isSpeaking?: boolean;
  isMuted?: boolean;
  duplicate?: boolean;
  notes?: readonly string[];
}> = ({ userId, label, shortId, state, stateClass, recipient, isSpeaking, isMuted, duplicate, notes }) => {
  const cls = ['voice-user-pill'];
  if (isSpeaking) cls.push('speaking');
  if (stateClass) cls.push(`state-${stateClass}`);

  return (
    <div className={cls.join(' ')} data-user-id={userId} data-testid={userId ? 'voice-participant' : 'voice-self'}>
      <div className="voice-user-pill-avatar">
        {label[0]?.toUpperCase()}
      </div>
      <div className="voice-user-pill-text">
        <span className="voice-user-pill-name">
          {label}
          {shortId && <code className="voice-user-pill-shortid">{shortId}</code>}
          {recipient && (
            <span className="voice-user-pill-key" title="Receives your current call key" aria-label="Receives your current call key">
              <Icon name="lock" size={10} />
            </span>
          )}
          {duplicate && (
            <span className="voice-user-pill-dup" title="Another participant has the same name">
              Same name as another participant
            </span>
          )}
        </span>
        {state && <span className="voice-user-pill-state">{state}</span>}
        {notes && notes.length > 0 && (
          <span className="voice-user-pill-notes">
            {notes.map(n => <span key={n} className="voice-user-pill-note">{n}</span>)}
          </span>
        )}
      </div>
      {isMuted && <span className="voice-user-pill-icon"><Icon name="mic-off" size={12} /></span>}
    </div>
  );
};
