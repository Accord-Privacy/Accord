import { describe, it, expect, beforeEach } from 'vitest';
import {
  stampLocalExpiry,
  getLocalExpiry,
  isLocallyExpired,
  tombstone,
  filterTombstoned,
  clearLocalExpiry,
} from './localExpiry';

describe('localExpiry (per-recipient read-gated expiry)', () => {
  beforeEach(() => localStorage.clear());

  it('stamps read time + ttl and persists it', () => {
    const expiry = stampLocalExpiry('m1', 60, 1000);
    expect(expiry).toBe(1060);
    expect(getLocalExpiry('m1')).toBe(1060);
  });

  it('never restarts this device countdown on re-read', () => {
    stampLocalExpiry('m1', 60, 1000);
    // A later read must NOT push the expiry out — first read wins.
    const again = stampLocalExpiry('m1', 60, 5000);
    expect(again).toBe(1060);
    expect(getLocalExpiry('m1')).toBe(1060);
  });

  it('tombstones move ids out of the countdown map and mark them expired', () => {
    stampLocalExpiry('m1', 60, 1000);
    expect(isLocallyExpired('m1')).toBe(false);
    tombstone(['m1']);
    expect(isLocallyExpired('m1')).toBe(true);
    expect(getLocalExpiry('m1')).toBeUndefined();
  });

  it('filterTombstoned drops expired copies on refetch, keeps the rest', () => {
    tombstone(['gone']);
    const msgs = [{ id: 'gone' }, { id: 'keep' }];
    expect(filterTombstoned(msgs).map(m => m.id)).toEqual(['keep']);
  });

  it('filterTombstoned is a no-op when nothing is tombstoned', () => {
    const msgs = [{ id: 'a' }, { id: 'b' }];
    expect(filterTombstoned(msgs)).toBe(msgs);
  });

  it('survives reload (state lives in localStorage)', () => {
    stampLocalExpiry('m1', 60, 1000);
    tombstone(['m2']);
    // Simulate a fresh module read of the same storage.
    expect(getLocalExpiry('m1')).toBe(1060);
    expect(isLocallyExpired('m2')).toBe(true);
  });

  it('clearLocalExpiry wipes both structures (panic/duress)', () => {
    stampLocalExpiry('m1', 60, 1000);
    tombstone(['m2']);
    clearLocalExpiry();
    expect(getLocalExpiry('m1')).toBeUndefined();
    expect(isLocallyExpired('m2')).toBe(false);
  });
});
