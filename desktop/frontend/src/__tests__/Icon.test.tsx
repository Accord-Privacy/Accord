import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Icon } from '../components/Icon';

describe('Icon', () => {
  it('renders an SVG for a known icon name', () => {
    const { container } = render(<Icon name="close" />);
    const svg = container.querySelector('svg');
    expect(svg).toBeInTheDocument();
  });

  it('renders correct SVG path for known icon', () => {
    const { container } = render(<Icon name="search" />);
    const path = container.querySelector('path');
    expect(path).toBeInTheDocument();
    expect(path?.getAttribute('d')).toBeTruthy();
  });

  it('falls back to a span with the name for unknown icons', () => {
    render(<Icon name="nonexistent-icon-xyz" />);
    expect(screen.getByText('nonexistent-icon-xyz')).toBeInTheDocument();
    // No SVG should be rendered
    const { container } = render(<Icon name="also-unknown" />);
    expect(container.querySelector('svg')).not.toBeInTheDocument();
  });

  it('applies the provided className to the SVG', () => {
    const { container } = render(<Icon name="star" className="my-icon-class" />);
    const svg = container.querySelector('svg');
    expect(svg).toHaveClass('my-icon-class');
  });

  it('always applies the base "icon" class to the SVG', () => {
    const { container } = render(<Icon name="pin" />);
    const svg = container.querySelector('svg');
    expect(svg).toHaveClass('icon');
  });

  it('falls back span also receives the className', () => {
    render(<Icon name="unknown-xyz" className="fallback-class" />);
    const span = screen.getByText('unknown-xyz');
    expect(span).toHaveClass('fallback-class');
  });

  it('uses the default size of 20', () => {
    const { container } = render(<Icon name="bolt" />);
    const svg = container.querySelector('svg');
    expect(svg?.getAttribute('width')).toBe('20');
    expect(svg?.getAttribute('height')).toBe('20');
  });

  it('respects a custom size prop', () => {
    const { container } = render(<Icon name="bolt" size={32} />);
    const svg = container.querySelector('svg');
    expect(svg?.getAttribute('width')).toBe('32');
    expect(svg?.getAttribute('height')).toBe('32');
  });

  it('renders known icons: pin, clock, bot, folder, link, shield', () => {
    const knownIcons = ['pin', 'clock', 'bot', 'folder', 'link', 'shield'];
    for (const name of knownIcons) {
      const { container } = render(<Icon name={name} />);
      expect(container.querySelector('svg')).toBeInTheDocument();
    }
  });
});
