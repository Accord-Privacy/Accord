/**
 * SPEC-03 REQ-11: how the voice panel labels participants.
 *
 * Display names come from the relay (C014), so they are never the only
 * label: every participant is also shown with its short id, and a name that
 * two users in the call share (the local user included) is marked on both.
 * The voice panel (`VoiceChat.tsx`) and the headless integration tests
 * (X-2) use these functions, so both mark exactly the same users.
 */

/** The member fields a display name is read from (`GET /nodes/:id/members`). */
export interface NamedMember {
  readonly user_id: string;
  readonly user?: { readonly display_name?: string | null } | null;
  readonly profile?: { readonly display_name?: string | null } | null;
}

/** Display names compare after Unicode normalization, case-insensitively. */
export function nameKey(name: string): string {
  return name.normalize('NFKC').trim().toLowerCase();
}

/** The name shown for `userId`: its member display name, or `fallback` (the short id). */
export function memberDisplayName(members: readonly NamedMember[], userId: string, fallback: string): string {
  const id = userId.toLowerCase();
  const member = members.find(m => m.user_id.toLowerCase() === id);
  return member?.user?.display_name || member?.profile?.display_name || fallback;
}

/** The keys (`nameKey`) of names that appear more than once in `names`. */
export function duplicateNameKeys(names: Iterable<string>): Set<string> {
  const counts = new Map<string, number>();
  for (const n of names) counts.set(nameKey(n), (counts.get(nameKey(n)) ?? 0) + 1);
  return new Set([...counts].filter(([, c]) => c > 1).map(([k]) => k));
}
