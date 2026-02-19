import { describe, it, expect, beforeEach, vi } from 'vitest';
import { applyTheme, getSavedTheme, themes } from '../themes';

describe('themes', () => {
  beforeEach(() => {
    // Reset CSS custom properties and localStorage
    document.documentElement.removeAttribute('style');
    document.body.removeAttribute('data-theme');
    localStorage.clear();
  });

  it('applyTheme sets CSS variables on :root', () => {
    applyTheme('dark');
    const root = document.documentElement;
    expect(root.style.getPropertyValue('--bg-content')).toBe(themes.dark.colors['--bg-content']);
    expect(root.style.getPropertyValue('--accent')).toBe(themes.dark.colors['--accent']);
  });

  it('applyTheme sets data-theme attribute on body', () => {
    applyTheme('light');
    expect(document.body.getAttribute('data-theme')).toBe('light');
  });

  it('applyTheme saves to localStorage', () => {
    applyTheme('midnight');
    expect(localStorage.getItem('accord_theme')).toBe('midnight');
  });

  it('getSavedTheme returns dark by default', () => {
    expect(getSavedTheme()).toBe('dark');
  });

  it('getSavedTheme returns saved value', () => {
    localStorage.setItem('accord_theme', 'light');
    expect(getSavedTheme()).toBe('light');
  });

  it('switching themes updates CSS variables', () => {
    applyTheme('dark');
    const darkBg = document.documentElement.style.getPropertyValue('--bg-content');
    applyTheme('light');
    const lightBg = document.documentElement.style.getPropertyValue('--bg-content');
    expect(darkBg).not.toBe(lightBg);
  });

  it('falls back to dark for unknown theme', () => {
    applyTheme('nonexistent');
    expect(document.body.getAttribute('data-theme')).toBe('dark');
  });
});
