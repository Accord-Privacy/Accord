import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ChatErrorBoundary, ModalErrorBoundary } from '../components/ErrorBoundary';

// Component that throws an error when shouldThrow is true
function ThrowError({ shouldThrow }: { shouldThrow: boolean }) {
  if (shouldThrow) {
    throw new Error('Test error');
  }
  return <div>Child content</div>;
}

describe('ChatErrorBoundary', () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    // Spy on console.error to verify error logging
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  it('renders children normally when no error occurs', () => {
    render(
      <ChatErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ChatErrorBoundary>
    );

    expect(screen.getByText('Child content')).toBeInTheDocument();
  });

  it('shows error UI when child throws an error', () => {
    render(
      <ChatErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ChatErrorBoundary>
    );

    expect(screen.getByText('Chat encountered an error')).toBeInTheDocument();
    expect(screen.getByText(/Something went wrong loading the chat/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try Again' })).toBeInTheDocument();
  });

  it('displays the chat emoji icon in error state', () => {
    render(
      <ChatErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ChatErrorBoundary>
    );

    expect(screen.getByText('💬')).toBeInTheDocument();
  });

  it('resets error state when Try Again button is clicked', () => {
    const { rerender } = render(
      <ChatErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ChatErrorBoundary>
    );

    // Error UI should be visible
    expect(screen.getByText('Chat encountered an error')).toBeInTheDocument();

    // Click Try Again
    const tryAgainButton = screen.getByRole('button', { name: 'Try Again' });
    tryAgainButton.click();

    // After reset, child will re-render without throwing (because shouldThrow is still true from props)
    // But we need to rerender with shouldThrow=false to simulate recovery
    rerender(
      <ChatErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ChatErrorBoundary>
    );

    expect(screen.getByText('Child content')).toBeInTheDocument();
    expect(screen.queryByText('Chat encountered an error')).not.toBeInTheDocument();
  });

  it('logs error via componentDidCatch', () => {
    render(
      <ChatErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ChatErrorBoundary>
    );

    // Verify console.error was called - React adds its own error logging
    expect(consoleErrorSpy).toHaveBeenCalled();
    // Find the call with our custom message
    const ourCall = consoleErrorSpy.mock.calls.find(call =>
      call[0] === 'Chat area error:'
    );
    expect(ourCall).toBeTruthy();
    expect(ourCall?.[1]).toBeInstanceOf(Error);
    expect(ourCall?.[1].message).toBe('Test error');
  });

  it('includes helpful message about sidebar still working', () => {
    render(
      <ChatErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ChatErrorBoundary>
    );

    expect(screen.getByText(/Your sidebar and other features still work/i)).toBeInTheDocument();
  });
});

describe('ModalErrorBoundary', () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  it('renders children normally when no error occurs', () => {
    render(
      <ModalErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ModalErrorBoundary>
    );

    expect(screen.getByText('Child content')).toBeInTheDocument();
  });

  it('shows simpler error message when child throws', () => {
    render(
      <ModalErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ModalErrorBoundary>
    );

    expect(screen.getByText('Something went wrong in this panel.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try Again' })).toBeInTheDocument();
  });

  it('does not show chat emoji icon (simpler UI)', () => {
    render(
      <ModalErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ModalErrorBoundary>
    );

    // Modal error boundary has simpler UI without emoji
    expect(screen.queryByText('💬')).not.toBeInTheDocument();
  });

  it('resets error state when Try Again button is clicked', () => {
    const { rerender } = render(
      <ModalErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ModalErrorBoundary>
    );

    expect(screen.getByText('Something went wrong in this panel.')).toBeInTheDocument();

    const tryAgainButton = screen.getByRole('button', { name: 'Try Again' });
    tryAgainButton.click();

    rerender(
      <ModalErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ModalErrorBoundary>
    );

    expect(screen.getByText('Child content')).toBeInTheDocument();
    expect(screen.queryByText('Something went wrong in this panel.')).not.toBeInTheDocument();
  });

  it('logs error via componentDidCatch with modal-specific prefix', () => {
    render(
      <ModalErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ModalErrorBoundary>
    );

    expect(consoleErrorSpy).toHaveBeenCalled();
    // Find the call with our custom message
    const ourCall = consoleErrorSpy.mock.calls.find(call =>
      call[0] === 'Modal/settings error:'
    );
    expect(ourCall).toBeTruthy();
    expect(ourCall?.[1]).toBeInstanceOf(Error);
  });
});
