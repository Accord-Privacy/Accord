import React, { useEffect, useState, useRef, useCallback } from 'react';
import ReactDOM from 'react-dom';
import { api } from './api';
import { UserProfile, Role, User } from './types';
import { avatarColor } from './avatarColor';

type ProfileTab = 'about' | 'mutual';

function getUserNote(userId: string): string {
  try { return localStorage.getItem(`accord-note:${userId}`) || ''; } catch { return ''; }
}
function setUserNote(userId: string, note: string): void {
  try {
    if (note) localStorage.setItem(`accord-note:${userId}`, note);
    else localStorage.removeItem(`accord-note:${userId}`);
  } catch { /* ignore */ }
}

export interface ProfileCardProps {
  userId: string;
  /** Screen position to anchor the card */
  anchorX: number;
  anchorY: number;
  /** Current user's ID to show Edit vs Message/Block */
  currentUserId: string;
  /** Token for API calls */
  token: string;
  /** Active node ID for fetching roles */
  nodeId?: string;
  /** Pre-loaded profile if available */
  profile?: UserProfile;
  /** Pre-loaded user object */
  user?: User;
  /** Pre-loaded member roles */
  roles?: Role[];
  /** Member joined_at timestamp */
  joinedAt?: number;
  /** Callbacks */
  onClose: () => void;
  onSendDm?: (user: User) => void;
  onBlock?: (userId: string, displayName: string) => void;
  onEditProfile?: () => void;
  /** Role color from parent */
  roleColor?: string;
}

const CARD_WIDTH = 340;
const CARD_MAX_HEIGHT = 520;

export const ProfileCard: React.FC<ProfileCardProps> = ({
  userId, anchorX, anchorY, currentUserId, token, nodeId,
  profile: initialProfile, user, roles: initialRoles, joinedAt,
  onClose, onSendDm, onBlock, onEditProfile, roleColor,
}) => {
  const [profile, setProfile] = useState<UserProfile | null>(initialProfile || null);
  const [roles, setRoles] = useState<Role[]>(initialRoles || []);
  const [activeTab, setActiveTab] = useState<ProfileTab>('about');
  const [note, setNote] = useState(() => getUserNote(userId));
  const [noteEditing, setNoteEditing] = useState(false);
  const cardRef = useRef<HTMLDivElement>(null);

  const saveNote = useCallback((value: string) => {
    setNote(value);
    setUserNote(userId, value);
  }, [userId]);

  // Fetch profile if not provided
  useEffect(() => {
    if (!initialProfile && token) {
      api.getUserProfile(userId, token).then(setProfile).catch(() => {});
    }
  }, [userId, token, initialProfile]);

  // Fetch roles if not provided
  useEffect(() => {
    if (!initialRoles && nodeId && token) {
      api.getMemberRoles(nodeId, userId, token).then(setRoles).catch(() => {});
    }
  }, [userId, nodeId, token, initialRoles]);

  // Click outside to close
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (cardRef.current && !cardRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    // Escape to close
    const keyHandler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('mousedown', handler);
    document.addEventListener('keydown', keyHandler);
    return () => { document.removeEventListener('mousedown', handler); document.removeEventListener('keydown', keyHandler); };
  }, [onClose]);

  // Position card to stay on screen
  const getPosition = () => {
    let x = anchorX + 8;
    let y = anchorY - 60;
    if (x + CARD_WIDTH > window.innerWidth - 16) x = anchorX - CARD_WIDTH - 8;
    if (y + CARD_MAX_HEIGHT > window.innerHeight - 16) y = window.innerHeight - CARD_MAX_HEIGHT - 16;
    if (y < 16) y = 16;
    if (x < 16) x = 16;
    return { left: x, top: y };
  };

  const pos = getPosition();
  const isSelf = userId === currentUserId;
  const displayName = profile?.display_name || user?.display_name || 'Unknown';
  const username = user?.public_key_hash ? user.public_key_hash.substring(0, 16) : userId.substring(0, 16);
  const bannerColor = roleColor || avatarColor(userId);

  const avatarUrl = api.getUserAvatarUrl(userId);

  return ReactDOM.createPortal(
    <div className="profile-card-overlay" onClick={onClose}>
      <div
        ref={cardRef}
        className="profile-card"
        style={{ left: pos.left, top: pos.top }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Banner */}
        <div className="profile-card-banner" style={{
          background: `linear-gradient(135deg, ${bannerColor}, ${bannerColor}88)`,
        }} />

        {/* Avatar */}
        <div className="profile-card-avatar-ring">
          <div className="profile-card-avatar" style={{ background: avatarColor(userId) }}>
            <img
              src={avatarUrl}
              alt={displayName[0]}
              onError={(e) => {
                const img = e.target as HTMLImageElement; img.style.display = 'none'; img.removeAttribute('src');
                if (img.parentElement) img.parentElement.textContent = displayName[0];
              }}
            />
          </div>
        </div>

        {/* Body */}
        <div className="profile-card-body">
          <div className="profile-card-names">
            <div className="profile-card-display-name" style={{ color: roleColor || undefined }}>
              {displayName}
            </div>
            <div className="profile-card-username">{username}</div>
          </div>

          {/* Custom Status */}
          {profile?.custom_status && (
            <div className="profile-card-status">{profile.custom_status}</div>
          )}

          <div className="profile-card-divider" />

          {/* Tabs */}
          <div className="profile-card-tabs">
            <button
              className={`profile-card-tab${activeTab === 'about' ? ' profile-card-tab-active' : ''}`}
              onClick={() => setActiveTab('about')}
            >About Me</button>
            <button
              className={`profile-card-tab${activeTab === 'mutual' ? ' profile-card-tab-active' : ''}`}
              onClick={() => setActiveTab('mutual')}
            >Mutual Nodes</button>
          </div>

          {/* Tab Content */}
          {activeTab === 'about' ? (
            <div className="profile-card-tab-content">
              {/* About / Bio */}
              {profile?.bio && (
                <div className="profile-card-section">
                  <div className="profile-card-section-title">ABOUT ME</div>
                  <div className="profile-card-bio">{profile.bio}</div>
                </div>
              )}

              {/* Roles */}
              {roles.length > 0 && (
                <div className="profile-card-section">
                  <div className="profile-card-section-title">ROLES</div>
                  <div className="profile-card-roles">
                    {roles.map(role => (
                      <span key={role.id} className="profile-card-role-pill" style={{
                        borderColor: role.color || 'var(--text-muted)',
                        color: role.color || 'var(--text-secondary)',
                      }}>
                        <span className="profile-card-role-dot" style={{
                          backgroundColor: role.color || 'var(--text-muted)',
                        }} />
                        {role.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Member Since */}
              {joinedAt != null && joinedAt > 0 && (
                <div className="profile-card-section">
                  <div className="profile-card-section-title">MEMBER SINCE</div>
                  <div className="profile-card-member-since">
                    {new Date(joinedAt < 1e12 ? joinedAt * 1000 : joinedAt).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })}
                  </div>
                </div>
              )}

              {/* Note */}
              <div className="profile-card-section">
                <div className="profile-card-section-title">NOTE</div>
                {noteEditing ? (
                  <textarea
                    className="profile-card-note-input"
                    value={note}
                    placeholder="Click to add a note"
                    onChange={(e) => saveNote(e.target.value)}
                    onBlur={() => setNoteEditing(false)}
                    autoFocus
                    rows={3}
                  />
                ) : (
                  <div
                    className="profile-card-note-display"
                    onClick={() => setNoteEditing(true)}
                  >
                    {note || 'Click to add a note'}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="profile-card-tab-content">
              <div className="profile-card-section">
                <div className="profile-card-section-title">MUTUAL NODES</div>
                {nodeId ? (
                  <div className="profile-card-mutual-node">
                    <span className="profile-card-mutual-node-dot" />
                    <span>Current Node</span>
                  </div>
                ) : (
                  <div className="profile-card-member-since">No mutual nodes</div>
                )}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="profile-card-actions">
            {isSelf ? (
              <button className="profile-card-btn profile-card-btn-primary" onClick={onEditProfile}>
                Edit Profile
              </button>
            ) : (
              <>
                <button className="profile-card-btn profile-card-btn-primary" onClick={() => user && onSendDm?.(user)}>
                  Message
                </button>
                <button className="profile-card-btn profile-card-btn-secondary" disabled title="Coming soon">
                  Add Friend
                </button>
                <button className="profile-card-btn profile-card-btn-danger" onClick={() => onBlock?.(userId, displayName)}>
                  Block
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
};
