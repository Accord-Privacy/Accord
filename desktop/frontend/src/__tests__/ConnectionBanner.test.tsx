import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { ConnectionBanner } from '../components/ConnectionBanner';

describe('ConnectionBanner', () => {
  const mockOnRetry = vi.fn();

  beforeEach(() => {
    mockOnRetry.mockClear();
  });

  it('is hidden when status is connected', () => {
    const { container } = render(
      <ConnectionBanner
        connectionInfo={{ status: 'connected', reconnectAttempt: 0 }}
        onRetry={mockOnRetry}
      />
    );

    const banner = container.querySelector('.connection-banner');
    expect(banner).toBeInTheDocument();
    expect(banner).toHaveClass('connection-banner--hidden');
    expect(banner).toHaveAttribute('aria-hidden', 'true');
  });

  it('shows "Reconnecting..." with spinner when reconnecting with low attempt count', () => {
    render(
      <ConnectionBanner
        connectionInfo={{ status: 'reconnecting', reconnectAttempt: 1 }}
        onRetry={mockOnRetry}
      />
    );

    expect(screen.getByText('Reconnecting...')).toBeInTheDocument();
    const banner = screen.getByRole('alert');
    expect(banner).toHaveClass('connection-banner--reconnecting');
    expect(banner.querySelector('.connection-spinner')).toBeInTheDocument();
  });

  it('shows "Reconnecting..." for reconnectAttempt = 2 (below threshold)', () => {
    render(
      <ConnectionBanner
        connectionInfo={{ status: 'reconnecting', reconnectAttempt: 2 }}
        onRetry={mockOnRetry}
      />
    );

    expect(screen.getByText('Reconnecting...')).toBeInTheDocument();
    expect(screen.queryByText(/Connection lost/)).not.toBeInTheDocument();
  });

  it('shows "Connection lost. Click to retry." when reconnectAttempt >= 3', () => {
    render(
      <ConnectionBanner
        connectionInfo={{ status: 'reconnecting', reconnectAttempt: 3 }}
        onRetry={mockOnRetry}
      />
    );

    expect(screen.getByText('Connection lost. Click to retry.')).toBeInTheDocument();
    const banner = screen.getByRole('alert');
    expect(banner).toHaveClass('connection-banner--failed');
    expect(banner.querySelector('.connection-spinner')).not.toBeInTheDocument();
  });

  it('shows failed state for reconnectAttempt > 3', () => {
    render(
      <ConnectionBanner
        connectionInfo={{ status: 'reconnecting', reconnectAttempt: 5 }}
        onRetry={mockOnRetry}
      />
    );

    expect(screen.getByText('Connection lost. Click to retry.')).toBeInTheDocument();
  });

  it('calls onRetry when clicking in failed state', () => {
    render(
      <ConnectionBanner
        connectionInfo={{ status: 'reconnecting', reconnectAttempt: 3 }}
        onRetry={mockOnRetry}
      />
    );

    const banner = screen.getByRole('alert');
    banner.click();

    expect(mockOnRetry).toHaveBeenCalledTimes(1);
  });

  it('does not call onRetry when clicking in reconnecting state (attempt < 3)', () => {
    render(
      <ConnectionBanner
        connectionInfo={{ status: 'reconnecting', reconnectAttempt: 1 }}
        onRetry={mockOnRetry}
      />
    );

    const banner = screen.getByRole('alert');
    banner.click();

    expect(mockOnRetry).not.toHaveBeenCalled();
  });

  it('returns null when disconnected with reconnectAttempt = 0 (initial state)', () => {
    const { container } = render(
      <ConnectionBanner
        connectionInfo={{ status: 'disconnected', reconnectAttempt: 0 }}
        onRetry={mockOnRetry}
      />
    );

    expect(container.firstChild).toBeNull();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows banner when disconnected with reconnectAttempt > 0', () => {
    render(
      <ConnectionBanner
        connectionInfo={{ status: 'disconnected', reconnectAttempt: 1 }}
        onRetry={mockOnRetry}
      />
    );

    // Disconnected with attempts should show reconnecting state
    expect(screen.getByText('Reconnecting...')).toBeInTheDocument();
  });

  it('has proper alert role for accessibility', () => {
    render(
      <ConnectionBanner
        connectionInfo={{ status: 'reconnecting', reconnectAttempt: 1 }}
        onRetry={mockOnRetry}
      />
    );

    expect(screen.getByRole('alert')).toBeInTheDocument();
  });
});
