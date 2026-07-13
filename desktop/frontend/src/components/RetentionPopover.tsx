import { useEffect, useRef, useState } from 'react';
import { Icon } from './Icon';
import type { Role, NodeMember, User } from '../types';

/**
 * Per-message retention chosen at send time.
 *
 * - `ttlSecs` alone  → plain disappearing: sender stamps expires_at = now + ttl.
 * - with users/roles → read-gated: relay starts the ttl only once every required
 *   reader has seen it. Each reader's own client also drops its copy at read+ttl,
 *   so it lingers for those who haven't opened it.
 */
export interface MessageGate {
  ttlSecs: number;
  users: string[];
  roles: string[];
}

const DURATIONS: Array<{ label: string; secs: number }> = [
  { label: '5 min', secs: 5 * 60 },
  { label: '1 hour', secs: 60 * 60 },
  { label: '8 hours', secs: 8 * 60 * 60 },
  { label: '1 day', secs: 24 * 60 * 60 },
  { label: '1 week', secs: 7 * 24 * 60 * 60 },
];

export function formatDuration(secs: number): string {
  const d = DURATIONS.find(x => x.secs === secs);
  if (d) return d.label;
  if (secs % 86400 === 0) return `${secs / 86400}d`;
  if (secs % 3600 === 0) return `${secs / 3600}h`;
  if (secs % 60 === 0) return `${secs / 60}m`;
  return `${secs}s`;
}

interface Props {
  gate: MessageGate | null;
  onChange: (gate: MessageGate | null) => void;
  members: Array<NodeMember & { user: User }>;
  roles: Role[];
  /** Hidden in DMs / when no channel is active. */
  disabled?: boolean;
}

export function RetentionPopover({ gate, onChange, members, roles, disabled }: Props) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const active = !!gate;
  const ttl = gate?.ttlSecs ?? DURATIONS[1].secs;
  const users = gate?.users ?? [];
  const gateRoles = gate?.roles ?? [];

  const setTtl = (secs: number) => onChange({ ttlSecs: secs, users, roles: gateRoles });
  const toggleUser = (id: string) =>
    onChange({ ttlSecs: ttl, roles: gateRoles, users: users.includes(id) ? users.filter(u => u !== id) : [...users, id] });
  const toggleRole = (id: string) =>
    onChange({ ttlSecs: ttl, users, roles: gateRoles.includes(id) ? gateRoles.filter(r => r !== id) : [...gateRoles, id] });

  const summary = !active
    ? 'Message retention'
    : users.length || gateRoles.length
      ? `Vanish ${formatDuration(ttl)} after seen`
      : `Vanish after ${formatDuration(ttl)}`;

  return (
    <div className="retention-popover-root" ref={rootRef}>
      <button
        type="button"
        className={`input-icon-btn${active ? ' input-icon-btn-active' : ''}`}
        title={summary}
        aria-label={summary}
        aria-pressed={active}
        disabled={disabled}
        onClick={() => setOpen(o => !o)}
      >
        <Icon name="clock" size={18} />
      </button>

      {open && (
        <div className="retention-popover" role="dialog" aria-label="Message retention">
          <div className="retention-popover-header">
            <span>Disappearing message</span>
            {active && (
              <button type="button" className="retention-clear" onClick={() => { onChange(null); }}>
                Off
              </button>
            )}
          </div>

          <div className="retention-section-label">Vanishes after</div>
          <div className="retention-durations">
            {DURATIONS.map(d => (
              <button
                key={d.secs}
                type="button"
                className={`retention-chip${active && ttl === d.secs ? ' retention-chip-active' : ''}`}
                onClick={() => setTtl(d.secs)}
              >
                {d.label}
              </button>
            ))}
          </div>

          {active && (
            <>
              <div className="retention-section-label">
                Only after seen by <span className="retention-hint">(optional)</span>
              </div>
              <p className="retention-explainer">
                The timer starts only once these people have opened the message, and it stays for
                anyone who hasn't read it yet.
              </p>

              {roles.length > 0 && (
                <div className="retention-picker-group">
                  {roles.map(r => (
                    <button
                      key={r.id}
                      type="button"
                      className={`retention-pill${gateRoles.includes(r.id) ? ' retention-pill-active' : ''}`}
                      style={r.color ? { borderColor: r.color } : undefined}
                      onClick={() => toggleRole(r.id)}
                    >
                      @{r.name}
                    </button>
                  ))}
                </div>
              )}

              <div className="retention-picker-group retention-picker-members">
                {members.map(m => (
                  <button
                    key={m.user_id}
                    type="button"
                    className={`retention-pill${users.includes(m.user_id) ? ' retention-pill-active' : ''}`}
                    onClick={() => toggleUser(m.user_id)}
                  >
                    {m.user.display_name || m.user_id.slice(0, 6)}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
