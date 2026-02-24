import React from "react";
import { useAppContext } from "./AppContext";
import { api } from "../api";
import { NodeMember, User } from "../types";
import { getCombinedTrust, getTrustIndicator, CLIENT_BUILD_HASH } from "../buildHash";
import containerStyles from './channel/MemberListContainer.module.css';
import itemStyles from './channel/MemberListItem.module.css';
import clsx from 'clsx';

export const MemberSidebar: React.FC = () => {
  const ctx = useAppContext();

  if (!ctx.showMemberSidebar) return null;

  const currentUserId = localStorage.getItem('accord_user_id');
  const renderMember = (member: NodeMember & { user: User }) => {
    const isCurrentUser = member.user_id === currentUserId;
    const presence = ctx.getPresenceStatus(member.user_id);
    const isOffline = presence === 'offline';

    return (
      <div
        key={member.user?.id || member.user_id}
        className={clsx(itemStyles.button, isOffline && itemStyles.buttonOffline)}
        onClick={(e) => {
          ctx.setProfileCardTarget({
            userId: member.user_id, x: e.clientX, y: e.clientY,
            user: member.user, profile: member.profile,
            roles: ctx.memberRolesMap[member.user_id],
            joinedAt: member.joined_at, roleColor: ctx.getMemberRoleColor(member.user_id),
          });
        }}
        onContextMenu={(e) => ctx.handleContextMenu(e, member.user_id, member.public_key_hash, ctx.displayName(member.user), member.profile?.bio, member.user)}
      >
        <div className={itemStyles.grid}>
          <div className={itemStyles.content}>
            <div className={itemStyles.avatarContainer}>
              <div style={{
                width: '32px', height: '32px', borderRadius: '50%', overflow: 'hidden',
                position: 'relative', flexShrink: 0,
              }}>
                <img
                  src={`${api.getUserAvatarUrl(member.user_id)}`}
                  alt={ctx.displayName(member.user)[0]}
                  style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                  onError={(e) => {
                    const img = e.target as HTMLImageElement;
                    img.style.display = 'none';
                    if (img.parentElement) {
                      img.parentElement.textContent = ctx.displayName(member.user)[0];
                      img.parentElement.setAttribute('style', 'width:32px;height:32px;border-radius:50%;background:var(--brand-primary);color:white;display:flex;align-items:center;justify-content:center;font-weight:600;font-size:14px;');
                    }
                  }}
                />
                {/* Presence dot */}
                <span style={{
                  position: 'absolute', bottom: '-1px', right: '-1px',
                  width: '10px', height: '10px', borderRadius: '50%',
                  border: '2px solid var(--background-secondary-lighter)',
                  backgroundColor: presence === 'online' ? 'var(--status-online, #3ba55c)'
                    : presence === 'idle' ? 'var(--status-idle, #faa61a)'
                    : presence === 'dnd' ? 'var(--status-danger, #ed4245)'
                    : 'var(--text-tertiary-muted)',
                }} />
              </div>
            </div>
            <div className={itemStyles.userInfoContainer}>
              <div className={itemStyles.nameContainer}>
                {isCurrentUser && (
                  <span style={{
                    width: '8px', height: '8px', borderRadius: '50%', marginRight: '4px', flexShrink: 0,
                    backgroundColor: (() => {
                      const trust = getCombinedTrust(CLIENT_BUILD_HASH, ctx.serverBuildHash, ctx.knownHashes);
                      return getTrustIndicator(trust).color;
                    })(),
                  }} />
                )}
                <span className={itemStyles.name} style={{ color: ctx.getMemberRoleColor(member.user_id) || undefined }}>
                  {ctx.displayName(member.user)}
                </span>
              </div>
              {member.profile?.custom_status && (
                <span className={itemStyles.memberCustomStatus}>{member.profile.custom_status}</span>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  };

  const hoistedRoles = ctx.nodeRoles.filter(r => r.hoist).sort((a, b) => b.position - a.position);
  const membersWithUser = ctx.sortedMembers.filter(m => m.user);

  const renderSection = (title: string, members: Array<NodeMember & { user: User }>, color?: string | null) => (
    <React.Fragment key={title}>
      <div style={{
        padding: '16px 8px 4px',
        fontSize: '11px', fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.02em',
        color: color || 'var(--text-tertiary-muted)',
      }}>
        {title} — {members.length}
      </div>
      {members.map(m => renderMember(m))}
    </React.Fragment>
  );

  if (hoistedRoles.length === 0) {
    const online = membersWithUser.filter(m => ctx.getPresenceStatus(m.user_id) !== 'offline');
    const offline = membersWithUser.filter(m => ctx.getPresenceStatus(m.user_id) === 'offline');
    return (
      <div className={containerStyles.memberListContainer}>
        <div className={containerStyles.memberListScroller} style={{ overflowY: 'auto' }}>
          {online.length > 0 && renderSection('Online', online)}
          {offline.length > 0 && renderSection('Offline', offline)}
        </div>
      </div>
    );
  }

  // With hoisted roles
  const assigned = new Set<string>();
  const sections: { name: string; color?: string | null; members: Array<NodeMember & { user: User }> }[] = [];

  for (const role of hoistedRoles) {
    const roleMembers = membersWithUser.filter(m => {
      if (assigned.has(m.user_id)) return false;
      const highest = ctx.getMemberHighestHoistedRole(m.user_id);
      return highest?.id === role.id;
    });
    roleMembers.forEach(m => assigned.add(m.user_id));
    sections.push({ name: role.name, color: role.color, members: roleMembers });
  }

  const unassigned = membersWithUser.filter(m => !assigned.has(m.user_id));
  const online = unassigned.filter(m => ctx.getPresenceStatus(m.user_id) !== 'offline');
  const offline = unassigned.filter(m => ctx.getPresenceStatus(m.user_id) === 'offline');

  return (
    <div className={containerStyles.memberListContainer}>
      <div className={containerStyles.memberListScroller} style={{ overflowY: 'auto' }}>
        {sections.filter(s => s.members.length > 0).map(s => renderSection(s.name, s.members, s.color))}
        {online.length > 0 && renderSection('Online', online)}
        {offline.length > 0 && renderSection('Offline', offline)}
        {membersWithUser.length === 0 && ctx.members.length === 0 && (
          <div style={{ padding: '16px', textAlign: 'center', color: 'var(--text-tertiary-muted)', fontSize: '13px' }}>
            {ctx.nodes.length === 0 ? 'Join or create a node to see members' : 'No members loaded'}
          </div>
        )}
      </div>
    </div>
  );
};
