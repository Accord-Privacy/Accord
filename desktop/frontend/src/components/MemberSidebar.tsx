import React from "react";
import { useAppContext } from "./AppContext";
import { api } from "../api";
import { NodeMember, User } from "../types";

export const MemberSidebar: React.FC = () => {
  const ctx = useAppContext();

  if (!ctx.showMemberSidebar) return null;

  const currentUserId = localStorage.getItem('accord_user_id');
  const canKick = ctx.selectedNodeId && ctx.hasPermission(ctx.selectedNodeId, 'KickMembers');

  const renderMember = (member: NodeMember & { user: User }) => {
    const isCurrentUser = member.user_id === currentUserId;
    const presence = ctx.getPresenceStatus(member.user_id);
    return (
      <div key={member.user?.id || member.user_id} className={`member ${presence === 'offline' ? 'member-offline' : ''}`}
        onClick={(e) => { ctx.setProfileCardTarget({ userId: member.user_id, x: e.clientX, y: e.clientY, user: member.user, profile: member.profile, roles: ctx.memberRolesMap[member.user_id], joinedAt: member.joined_at, roleColor: ctx.getMemberRoleColor(member.user_id) }); }}
        onContextMenu={(e) => ctx.handleContextMenu(e, member.user_id, member.public_key_hash, ctx.displayName(member.user), member.profile?.bio, member.user)}
      >
        <div className="member-avatar-wrapper">
          <div className="member-avatar">
            <img 
              src={`${api.getUserAvatarUrl(member.user_id)}`}
              alt={ctx.displayName(member.user)[0]}
              style={{ width: '100%', height: '100%', objectFit: 'cover', borderRadius: '50%' }}
              onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; (e.target as HTMLImageElement).parentElement!.textContent = ctx.displayName(member.user)[0]; }}
            />
          </div>
          <span className={`presence-dot presence-${presence}`} title={presence}></span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span className="member-name" style={{ color: ctx.getMemberRoleColor(member.user_id) || undefined }}>{ctx.displayName(member.user)}</span>
            <span className="member-role-badge" title={member.role}>{ctx.getRoleBadge(member.role)}</span>
          </div>
          {member.profile?.custom_status && (
            <span className="member-custom-status">{member.profile.custom_status}</span>
          )}
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '4px' }}>
          {!isCurrentUser && (
            <button onClick={(e) => { e.stopPropagation(); ctx.openDmWithUser(member.user); }} className="member-action-btn" title="Send DM">DM</button>
          )}
          {canKick && !isCurrentUser && (
            <button onClick={(e) => { e.stopPropagation(); ctx.setShowRolePopup({ userId: member.user_id, x: e.clientX, y: e.clientY }); }} className="member-action-btn" title="Manage roles">Roles</button>
          )}
          {canKick && !isCurrentUser && (
            <button onClick={(e) => { e.stopPropagation(); ctx.handleKickMember(member.user_id, ctx.displayName(member.user)); }} className="member-action-btn danger" title="Kick member">Kick</button>
          )}
        </div>
      </div>
    );
  };

  const hoistedRoles = ctx.nodeRoles.filter(r => r.hoist).sort((a, b) => b.position - a.position);
  const membersWithUser = ctx.sortedMembers.filter(m => m.user);

  if (hoistedRoles.length === 0) {
    const online = membersWithUser.filter(m => ctx.getPresenceStatus(m.user_id) !== 'offline');
    const offline = membersWithUser.filter(m => ctx.getPresenceStatus(m.user_id) === 'offline');
    return (
      <div className="member-sidebar">
        <div className="member-header">Members — {ctx.members.filter(m => m.user).length}</div>
        {online.length > 0 && (
          <>
            <div className="role-section-header">Online — {online.length}</div>
            {online.map(m => renderMember(m))}
          </>
        )}
        {offline.length > 0 && (
          <>
            <div className="role-section-header" style={{ color: '#72767d' }}>Offline — {offline.length}</div>
            {offline.map(m => renderMember(m))}
          </>
        )}
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
    <div className="member-sidebar">
      <div className="member-header">Members — {ctx.members.filter(m => m.user).length}</div>
      {sections.filter(s => s.members.length > 0).map(s => (
        <React.Fragment key={s.name}>
          <div className="role-section-header" style={{ color: s.color || undefined }}>{s.name} — {s.members.length}</div>
          {s.members.map(m => renderMember(m))}
        </React.Fragment>
      ))}
      {online.length > 0 && (
        <>
          <div className="role-section-header">Online — {online.length}</div>
          {online.map(m => renderMember(m))}
        </>
      )}
      {offline.length > 0 && (
        <>
          <div className="role-section-header" style={{ color: '#72767d' }}>Offline — {offline.length}</div>
          {offline.map(m => renderMember(m))}
        </>
      )}
      {membersWithUser.length === 0 && ctx.members.length === 0 && (
        <div className="members-empty">
          {ctx.nodes.length === 0 ? 'Join or create a node to see members' : 'No members loaded'}
        </div>
      )}
    </div>
  );
};
