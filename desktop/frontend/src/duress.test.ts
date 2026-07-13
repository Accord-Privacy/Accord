import { describe, it, expect, beforeEach } from 'vitest';
import { setDuressPassword, isDuressPassword, isDuressConfigured } from './duress';

describe('duress password', () => {
  beforeEach(() => localStorage.clear());

  it('is not configured by default', () => {
    expect(isDuressConfigured()).toBe(false);
    expect(isDuressPassword('anything')).toBe(false);
  });

  it('recognizes the configured duress password and rejects others', () => {
    setDuressPassword('duress-pass-123', 'real-pass-456');
    expect(isDuressConfigured()).toBe(true);
    expect(isDuressPassword('duress-pass-123')).toBe(true);
    expect(isDuressPassword('real-pass-456')).toBe(false);
    expect(isDuressPassword('wrong')).toBe(false);
  });

  it('clears with null', () => {
    setDuressPassword('duress-pass-123', 'real-pass-456');
    setDuressPassword(null, 'real-pass-456');
    expect(isDuressConfigured()).toBe(false);
    expect(isDuressPassword('duress-pass-123')).toBe(false);
  });

  it('refuses a duress password equal to the real password', () => {
    expect(() => setDuressPassword('same-pass-123', 'same-pass-123')).toThrow(/differ/);
    expect(isDuressConfigured()).toBe(false);
  });

  it('refuses a too-short duress password', () => {
    expect(() => setDuressPassword('short', 'real-pass-456')).toThrow(/8 characters/);
  });

  it('stores only a salted verifier, never the password', () => {
    setDuressPassword('duress-pass-123', 'real-pass-456');
    const stored = localStorage.getItem('accord_duress_v')!;
    expect(stored).not.toContain('duress-pass-123');
    // salt(16) + verifier(32) = 48 bytes → base64
    expect(atob(stored).length).toBe(48);
  });

  it('uses a random salt (two configs of the same password differ)', () => {
    setDuressPassword('duress-pass-123', 'real-pass-456');
    const a = localStorage.getItem('accord_duress_v');
    setDuressPassword('duress-pass-123', 'real-pass-456');
    const b = localStorage.getItem('accord_duress_v');
    expect(a).not.toBe(b);
    // Both still verify.
    expect(isDuressPassword('duress-pass-123')).toBe(true);
  });
});
