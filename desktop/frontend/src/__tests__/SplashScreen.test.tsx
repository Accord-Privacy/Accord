import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { SplashScreen } from '../components/SplashScreen';

describe('SplashScreen', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('renders when not ready', () => {
    const { container } = render(<SplashScreen ready={false} />);
    expect(container.querySelector('.splash-screen')).toBeInTheDocument();
  });

  it('displays the Accord logo with accent', () => {
    render(<SplashScreen ready={false} />);
    const accent = screen.getByText('A');
    expect(accent).toHaveClass('splash-accent');
    expect(screen.getByText('ccord')).toBeInTheDocument();
  });

  it('shows three loading dots', () => {
    const { container } = render(<SplashScreen ready={false} />);
    const dots = container.querySelectorAll('.splash-dot');
    expect(dots).toHaveLength(3);
  });

  it('displays "Initializing" status text', () => {
    render(<SplashScreen ready={false} />);
    expect(screen.getByText(/Initializing/i)).toBeInTheDocument();
  });

  it('does not apply fade-out class when not ready', () => {
    const { container } = render(<SplashScreen ready={false} />);
    const splash = container.querySelector('.splash-screen');
    expect(splash).not.toHaveClass('splash-fade-out');
  });

  it('applies fade-out class when ready becomes true', () => {
    const { container, rerender } = render(<SplashScreen ready={false} />);
    rerender(<SplashScreen ready={true} />);
    const splash = container.querySelector('.splash-screen');
    expect(splash).toHaveClass('splash-fade-out');
  });

  it('unmounts after 500ms when ready', () => {
    const { container, rerender } = render(<SplashScreen ready={false} />);
    expect(container.querySelector('.splash-screen')).toBeInTheDocument();

    rerender(<SplashScreen ready={true} />);
    expect(container.querySelector('.splash-screen')).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(container.querySelector('.splash-screen')).not.toBeInTheDocument();
  });

  it('does not unmount before 500ms when ready', () => {
    const { container, rerender } = render(<SplashScreen ready={false} />);
    rerender(<SplashScreen ready={true} />);

    act(() => {
      vi.advanceTimersByTime(400);
    });

    expect(container.querySelector('.splash-screen')).toBeInTheDocument();
  });

  it('cleans up timer on unmount', () => {
    const { unmount, rerender } = render(<SplashScreen ready={false} />);
    rerender(<SplashScreen ready={true} />);
    unmount();

    // Should not throw
    act(() => {
      vi.advanceTimersByTime(500);
    });
  });

  it('renders null if initially visible is false', () => {
    const { container, rerender } = render(<SplashScreen ready={false} />);

    rerender(<SplashScreen ready={true} />);
    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(container.firstChild).toBeNull();
  });

  it('maintains structure while fading out', () => {
    const { container, rerender } = render(<SplashScreen ready={false} />);
    rerender(<SplashScreen ready={true} />);

    expect(container.querySelector('.splash-logo')).toBeInTheDocument();
    expect(container.querySelector('.splash-loader')).toBeInTheDocument();
    expect(container.querySelector('.splash-status')).toBeInTheDocument();
  });

  it('renders all container elements correctly', () => {
    const { container } = render(<SplashScreen ready={false} />);

    expect(container.querySelector('.splash-screen')).toBeInTheDocument();
    expect(container.querySelector('.splash-logo')).toBeInTheDocument();
    expect(container.querySelector('.splash-loader')).toBeInTheDocument();
    expect(container.querySelector('.splash-status')).toBeInTheDocument();
  });
});
