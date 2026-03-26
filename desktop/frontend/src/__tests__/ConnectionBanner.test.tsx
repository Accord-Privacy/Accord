import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ConnectionBanner } from '../components/ConnectionBanner';
import type { ConnectionInfo } from '../ws';

const makeInfo = (
  status: ConnectionInfo['status'],
  reconnectAttempt = 0,
  maxReconnectAttempts = 10
): ConnectionInfo => ({ status, reconnectAttempt, maxReconnectAttempts });

describe('ConnectionBanner', () => {
  const onRetry = vi.fn();

  beforeEach(() => { vi.clearAllMocks(); });

  it('renders a hidden banner when connected', () => {
    const { container } = render(
      <ConnectionBanner connectionInfo={makeInfo('connected')} onRetry={onRetry} />
    );
    const banner = container.querySelector('.connection-banner--hidden');
    expect(banner).toBeInTheDocument();
  });

  it('renders nothing in the initial disconnected state (attempt 0)', () => {
    const { container } = render(
      <ConnectionBanner connectionInfo={makeInfo('disconnected', 0)} onRetry={onRetry} />
    );
    // Should render null — no banner element at all
    expect(container.firstChild).toBeNull();
  });

  it('shows reconnecting banner when reconnecting and under fail threshold', () => {
    render(
      <ConnectionBanner connectionInfo={makeInfo('reconnecting', 1)} onRetry={onRetry} />
    );
    expect(screen.getByText(/Reconnecting/i)).toBeInTheDocument();
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('shows failed banner when reconnect attempts >= 3', () => {
    render(
      <ConnectionBanner connectionInfo={makeInfo('reconnecting', 3)} onRetry={onRetry} />
    );
    expect(screen.getByText(/Connection lost/i)).toBeInTheDocument();
    expect(screen.getByText(/Click to retry/i)).toBeInTheDocument();
  });

  it('calls onRetry when failed banner is clicked', () => {
    render(
      <ConnectionBanner connectionInfo={makeInfo('reconnecting', 3)} onRetry={onRetry} />
    );
    fireEvent.click(screen.getByRole('alert'));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('does not call onRetry when reconnecting banner is clicked (not failed)', () => {
    render(
      <ConnectionBanner connectionInfo={makeInfo('reconnecting', 1)} onRetry={onRetry} />
    );
    fireEvent.click(screen.getByRole('alert'));
    expect(onRetry).not.toHaveBeenCalled();
  });

  it('applies failed CSS class when at fail threshold', () => {
    const { container } = render(
      <ConnectionBanner connectionInfo={makeInfo('reconnecting', 5)} onRetry={onRetry} />
    );
    expect(container.querySelector('.connection-banner--failed')).toBeInTheDocument();
  });

  it('applies reconnecting CSS class when below fail threshold', () => {
    const { container } = render(
      <ConnectionBanner connectionInfo={makeInfo('reconnecting', 2)} onRetry={onRetry} />
    );
    expect(container.querySelector('.connection-banner--reconnecting')).toBeInTheDocument();
  });
});
