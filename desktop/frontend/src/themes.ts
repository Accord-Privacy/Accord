// Theme definitions for Accord
// Each theme maps CSS variable names to values

export interface Theme {
  name: string;
  label: string;
  icon: string;
  colors: Record<string, string>;
  /** Preview swatch colors for the theme selector */
  preview: { bg: string; sidebar: string; accent: string; text: string };
}

const darkColors: Record<string, string> = {
  '--bg-darkest': '#1e1f22',
  '--bg-dark': '#2b2d31',
  '--bg-content': '#313338',
  '--bg-input': '#383a40',
  '--bg-hover': '#2e3035',
  '--bg-active': '#404249',
  '--bg-overlay': 'rgba(0, 0, 0, 0.85)',
  '--accent': '#5865f2',
  '--accent-hover': '#4752c4',
  '--accent-light': 'rgba(88, 101, 242, 0.15)',
  '--green': '#23a559',
  '--green-dark': '#1a7d41',
  '--red': '#da373c',
  '--red-dark': '#a12d31',
  '--yellow': '#f0b232',
  '--orange': '#e67e22',
  '--text-primary': '#f2f3f5',
  '--text-secondary': '#b5bac1',
  '--text-muted': '#949ba4',
  '--text-faint': '#6d6f78',
  '--border': '#1e1f22',
  '--border-subtle': 'rgba(255, 255, 255, 0.06)',
  '--shadow-low': '0 1px 0 rgba(0, 0, 0, 0.2), 0 1.5px 0 rgba(0, 0, 0, 0.05)',
  '--shadow-md': '0 4px 8px rgba(0, 0, 0, 0.24)',
  '--shadow-high': '0 8px 24px rgba(0, 0, 0, 0.4)',
};

const lightColors: Record<string, string> = {
  '--bg-darkest': '#e3e5e8',
  '--bg-dark': '#f2f3f5',
  '--bg-content': '#ffffff',
  '--bg-input': '#e3e5e8',
  '--bg-hover': '#ebedef',
  '--bg-active': '#d4d7dc',
  '--bg-overlay': 'rgba(0, 0, 0, 0.5)',
  '--accent': '#5865f2',
  '--accent-hover': '#4752c4',
  '--accent-light': 'rgba(88, 101, 242, 0.12)',
  '--green': '#23a559',
  '--green-dark': '#1a7d41',
  '--red': '#da373c',
  '--red-dark': '#a12d31',
  '--yellow': '#f0b232',
  '--orange': '#e67e22',
  '--text-primary': '#060607',
  '--text-secondary': '#4e5058',
  '--text-muted': '#6d6f78',
  '--text-faint': '#949ba4',
  '--border': '#e3e5e8',
  '--border-subtle': 'rgba(0, 0, 0, 0.08)',
  '--shadow-low': '0 1px 0 rgba(0, 0, 0, 0.08), 0 1.5px 0 rgba(0, 0, 0, 0.02)',
  '--shadow-md': '0 4px 8px rgba(0, 0, 0, 0.12)',
  '--shadow-high': '0 8px 24px rgba(0, 0, 0, 0.16)',
};

const midnightColors: Record<string, string> = {
  '--bg-darkest': '#000000',
  '--bg-dark': '#0a0a0a',
  '--bg-content': '#111111',
  '--bg-input': '#1a1a1a',
  '--bg-hover': '#161616',
  '--bg-active': '#222222',
  '--bg-overlay': 'rgba(0, 0, 0, 0.92)',
  '--accent': '#7289da',
  '--accent-hover': '#5b6eae',
  '--accent-light': 'rgba(114, 137, 218, 0.15)',
  '--green': '#23a559',
  '--green-dark': '#1a7d41',
  '--red': '#ed4245',
  '--red-dark': '#c93b3e',
  '--yellow': '#fee75c',
  '--orange': '#e67e22',
  '--text-primary': '#e0e0e0',
  '--text-secondary': '#a0a0a0',
  '--text-muted': '#707070',
  '--text-faint': '#505050',
  '--border': '#000000',
  '--border-subtle': 'rgba(255, 255, 255, 0.04)',
  '--shadow-low': '0 1px 0 rgba(0, 0, 0, 0.4), 0 1.5px 0 rgba(0, 0, 0, 0.1)',
  '--shadow-md': '0 4px 8px rgba(0, 0, 0, 0.5)',
  '--shadow-high': '0 8px 24px rgba(0, 0, 0, 0.7)',
};

const amoledColors: Record<string, string> = {
  '--bg-darkest': '#000000',
  '--bg-dark': '#000000',
  '--bg-content': '#000000',
  '--bg-input': '#1a1a1a',
  '--bg-hover': '#121212',
  '--bg-active': '#1e1e1e',
  '--bg-overlay': 'rgba(0, 0, 0, 0.95)',
  '--accent': '#5865f2',
  '--accent-hover': '#4752c4',
  '--accent-light': 'rgba(88, 101, 242, 0.15)',
  '--green': '#23a559',
  '--green-dark': '#1a7d41',
  '--red': '#da373c',
  '--red-dark': '#a12d31',
  '--yellow': '#f0b232',
  '--orange': '#e67e22',
  '--text-primary': '#ffffff',
  '--text-secondary': '#b0b0b0',
  '--text-muted': '#808080',
  '--text-faint': '#555555',
  '--border': '#1a1a1a',
  '--border-subtle': 'rgba(255, 255, 255, 0.06)',
  '--shadow-low': '0 1px 0 rgba(0, 0, 0, 0.4), 0 1.5px 0 rgba(0, 0, 0, 0.1)',
  '--shadow-md': '0 4px 8px rgba(0, 0, 0, 0.6)',
  '--shadow-high': '0 8px 24px rgba(0, 0, 0, 0.8)',
};

const nordColors: Record<string, string> = {
  '--bg-darkest': '#2E3440',
  '--bg-dark': '#3B4252',
  '--bg-content': '#434C5E',
  '--bg-input': '#4C566A',
  '--bg-hover': '#3B4252',
  '--bg-active': '#4C566A',
  '--bg-overlay': 'rgba(46, 52, 64, 0.92)',
  '--accent': '#88C0D0',
  '--accent-hover': '#6FAAB8',
  '--accent-light': 'rgba(136, 192, 208, 0.15)',
  '--green': '#A3BE8C',
  '--green-dark': '#8CAA74',
  '--red': '#BF616A',
  '--red-dark': '#A5464F',
  '--yellow': '#EBCB8B',
  '--orange': '#D08770',
  '--text-primary': '#ECEFF4',
  '--text-secondary': '#D8DEE9',
  '--text-muted': '#8FBCBB',
  '--text-faint': '#6d8286',
  '--border': '#2E3440',
  '--border-subtle': 'rgba(255, 255, 255, 0.06)',
  '--shadow-low': '0 1px 0 rgba(0, 0, 0, 0.3), 0 1.5px 0 rgba(0, 0, 0, 0.08)',
  '--shadow-md': '0 4px 8px rgba(0, 0, 0, 0.35)',
  '--shadow-high': '0 8px 24px rgba(0, 0, 0, 0.5)',
};

export const themes: Record<string, Theme> = {
  dark: {
    name: 'dark',
    label: 'Dark',
    icon: '🌙',
    colors: darkColors,
    preview: { bg: '#313338', sidebar: '#2b2d31', accent: '#5865f2', text: '#f2f3f5' },
  },
  light: {
    name: 'light',
    label: 'Light',
    icon: '☀️',
    colors: lightColors,
    preview: { bg: '#ffffff', sidebar: '#f2f3f5', accent: '#5865f2', text: '#060607' },
  },
  midnight: {
    name: 'midnight',
    label: 'Midnight',
    icon: '🌑',
    colors: midnightColors,
    preview: { bg: '#111111', sidebar: '#0a0a0a', accent: '#7289da', text: '#e0e0e0' },
  },
  amoled: {
    name: 'amoled',
    label: 'AMOLED',
    icon: '🖤',
    colors: amoledColors,
    preview: { bg: '#000000', sidebar: '#000000', accent: '#5865f2', text: '#ffffff' },
  },
  nord: {
    name: 'nord',
    label: 'Nord',
    icon: '❄️',
    colors: nordColors,
    preview: { bg: '#434C5E', sidebar: '#3B4252', accent: '#88C0D0', text: '#ECEFF4' },
  },
};

export type ThemeName = keyof typeof themes;

const STORAGE_KEY = 'accord_theme';

/** Apply a theme by setting CSS variables on :root */
export function applyTheme(name: string): void {
  const theme = themes[name] || themes.dark;
  const root = document.documentElement;
  for (const [prop, value] of Object.entries(theme.colors)) {
    root.style.setProperty(prop, value);
  }
  document.body.setAttribute('data-theme', theme.name);
  localStorage.setItem(STORAGE_KEY, theme.name);
}

/** Get the currently saved theme name */
export function getSavedTheme(): string {
  return localStorage.getItem(STORAGE_KEY) || 'dark';
}

/** Initialize theme on app load */
export function initTheme(): void {
  applyTheme(getSavedTheme());
  applyAccentColor(getSavedAccentColor());
  applyFontSize(getSavedFontSize());
}

/* ============ Accent Color ============ */
const ACCENT_STORAGE_KEY = 'accord_accent_color';

export const ACCENT_PRESETS = [
  '#5865f2', // Discord blue (default)
  '#eb459e', // Pink
  '#ed4245', // Red
  '#e67e22', // Orange
  '#f0b232', // Yellow
  '#23a559', // Green
  '#1abc9c', // Teal
  '#3498db', // Light blue
  '#9b59b6', // Purple
  '#e91e63', // Hot pink
];

export function applyAccentColor(color: string | null): void {
  if (!color) return;
  const root = document.documentElement;
  root.style.setProperty('--accent', color);
  // Derive hover (darken ~15%)
  const r = parseInt(color.slice(1, 3), 16);
  const g = parseInt(color.slice(3, 5), 16);
  const b = parseInt(color.slice(5, 7), 16);
  const darken = (v: number) => Math.max(0, Math.round(v * 0.82));
  root.style.setProperty('--accent-hover', `#${darken(r).toString(16).padStart(2, '0')}${darken(g).toString(16).padStart(2, '0')}${darken(b).toString(16).padStart(2, '0')}`);
  root.style.setProperty('--accent-light', `rgba(${r}, ${g}, ${b}, 0.15)`);
  localStorage.setItem(ACCENT_STORAGE_KEY, color);
}

export function getSavedAccentColor(): string | null {
  return localStorage.getItem(ACCENT_STORAGE_KEY);
}

export function clearAccentColor(): void {
  localStorage.removeItem(ACCENT_STORAGE_KEY);
  // Re-apply theme defaults
  applyTheme(getSavedTheme());
}

/* ============ Font Size ============ */
const FONT_SIZE_STORAGE_KEY = 'accord_font_size';

export const FONT_SIZE_OPTIONS = [
  { label: 'Small', value: 13 },
  { label: 'Normal', value: 15 },
  { label: 'Large', value: 17 },
  { label: 'Extra Large', value: 19 },
];

export function applyFontSize(size: number | null): void {
  if (!size) return;
  document.documentElement.style.setProperty('--font-size', `${size}px`);
  localStorage.setItem(FONT_SIZE_STORAGE_KEY, String(size));
}

export function getSavedFontSize(): number | null {
  const v = localStorage.getItem(FONT_SIZE_STORAGE_KEY);
  return v ? parseInt(v, 10) : null;
}
