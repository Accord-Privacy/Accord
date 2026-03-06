// Discord-style avatar colors (5 predefined colors)
const AVATAR_COLORS = ['#5865f2', '#57f287', '#fee75c', '#eb459e', '#ed4245'];

export function avatarColor(id: string): string {
  if (!id) return AVATAR_COLORS[0];
  let hash = 0;
  for (let i = 0; i < id.length; i++) hash = ((hash << 5) - hash + id.charCodeAt(i)) | 0;
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
}
