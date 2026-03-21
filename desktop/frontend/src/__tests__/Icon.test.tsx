import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { Icon } from '../components/Icon';

describe('Icon', () => {
  it('renders SVG for known icon name', () => {
    const { container } = render(<Icon name="pin" />);

    const svg = container.querySelector('svg');
    expect(svg).toBeInTheDocument();
    expect(svg?.querySelector('path')).toBeInTheDocument();
  });

  it('uses default size of 20 when size not specified', () => {
    const { container } = render(<Icon name="clock" />);

    const svg = container.querySelector('svg');
    expect(svg).toHaveAttribute('width', '20');
    expect(svg).toHaveAttribute('height', '20');
  });

  it('applies custom size when specified', () => {
    const { container } = render(<Icon name="bot" size={32} />);

    const svg = container.querySelector('svg');
    expect(svg).toHaveAttribute('width', '32');
    expect(svg).toHaveAttribute('height', '32');
  });

  it('applies small custom size', () => {
    const { container } = render(<Icon name="star" size={16} />);

    const svg = container.querySelector('svg');
    expect(svg).toHaveAttribute('width', '16');
    expect(svg).toHaveAttribute('height', '16');
  });

  it('has correct viewBox attribute', () => {
    const { container } = render(<Icon name="folder" />);

    const svg = container.querySelector('svg');
    expect(svg).toHaveAttribute('viewBox', '0 0 24 24');
  });

  it('applies custom className', () => {
    const { container } = render(<Icon name="link" className="custom-class" />);

    const svg = container.querySelector('svg');
    expect(svg).toHaveClass('icon');
    expect(svg).toHaveClass('custom-class');
  });

  it('always includes base icon class', () => {
    const { container } = render(<Icon name="shield" />);

    const svg = container.querySelector('svg');
    expect(svg).toHaveClass('icon');
  });

  it('applies custom style object', () => {
    const { container } = render(
      <Icon name="download" style={{ color: 'red', opacity: 0.5 }} />
    );

    const svg = container.querySelector('svg');
    // jsdom converts color names to rgb format
    expect(svg).toHaveStyle({ opacity: '0.5' });
    expect(svg?.style.color).toBeTruthy();
  });

  it('falls back to text span for unknown icon name', () => {
    render(<Icon name="unknown-icon-name" />);

    const span = screen.getByText('unknown-icon-name');
    expect(span.tagName).toBe('SPAN');
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
  });

  it('applies className to fallback span for unknown icon', () => {
    render(<Icon name="not-found" className="fallback-class" />);

    const span = screen.getByText('not-found');
    expect(span).toHaveClass('fallback-class');
  });

  it('renders different icons correctly', () => {
    const { container: container1 } = render(<Icon name="search" />);
    const { container: container2 } = render(<Icon name="settings" />);

    const path1 = container1.querySelector('path')?.getAttribute('d');
    const path2 = container2.querySelector('path')?.getAttribute('d');

    // Paths should be different for different icons
    expect(path1).toBeTruthy();
    expect(path2).toBeTruthy();
    expect(path1).not.toBe(path2);
  });

  it('uses currentColor fill for SVG', () => {
    const { container } = render(<Icon name="bell" />);

    const svg = container.querySelector('svg');
    expect(svg).toHaveAttribute('fill', 'currentColor');
  });
});
