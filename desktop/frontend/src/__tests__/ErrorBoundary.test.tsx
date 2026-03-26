import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ChatErrorBoundary, ModalErrorBoundary } from '../components/ErrorBoundary';

// A component that throws when `shouldThrow` is true
const Bomb = ({ shouldThrow }: { shouldThrow: boolean }) => {
  if (shouldThrow) throw new Error('Test explosion');
  return <div>Normal content</div>;
};

// Suppress console.error noise from React error boundary output
beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

describe('ChatErrorBoundary', () => {
  it('renders children when no error', () => {
    render(
      <ChatErrorBoundary>
        <div>Chat content</div>
      </ChatErrorBoundary>
    );
    expect(screen.getByText('Chat content')).toBeInTheDocument();
  });

  it('shows fallback UI when child throws', () => {
    render(
      <ChatErrorBoundary>
        <Bomb shouldThrow={true} />
      </ChatErrorBoundary>
    );
    expect(screen.getByText('Chat encountered an error')).toBeInTheDocument();
    expect(screen.getByText(/Something went wrong loading the chat/i)).toBeInTheDocument();
  });

  it('shows Try Again button in fallback', () => {
    render(
      <ChatErrorBoundary>
        <Bomb shouldThrow={true} />
      </ChatErrorBoundary>
    );
    expect(screen.getByText('Try Again')).toBeInTheDocument();
  });

  it('resets error state when Try Again is clicked', () => {
    // Use a controlled shouldThrow so we can change it after reset
    let shouldThrow = true;
    const { rerender } = render(
      <ChatErrorBoundary>
        <Bomb shouldThrow={shouldThrow} />
      </ChatErrorBoundary>
    );
    expect(screen.getByText('Try Again')).toBeInTheDocument();
    // Re-render with non-throwing child, then click reset
    shouldThrow = false;
    rerender(
      <ChatErrorBoundary>
        <Bomb shouldThrow={shouldThrow} />
      </ChatErrorBoundary>
    );
    fireEvent.click(screen.getByText('Try Again'));
    expect(screen.getByText('Normal content')).toBeInTheDocument();
  });

  it('does not show fallback when no error is thrown', () => {
    render(
      <ChatErrorBoundary>
        <Bomb shouldThrow={false} />
      </ChatErrorBoundary>
    );
    expect(screen.queryByText('Chat encountered an error')).not.toBeInTheDocument();
    expect(screen.getByText('Normal content')).toBeInTheDocument();
  });
});

describe('ModalErrorBoundary', () => {
  it('renders children when no error', () => {
    render(
      <ModalErrorBoundary>
        <div>Modal content</div>
      </ModalErrorBoundary>
    );
    expect(screen.getByText('Modal content')).toBeInTheDocument();
  });

  it('shows fallback UI when child throws', () => {
    render(
      <ModalErrorBoundary>
        <Bomb shouldThrow={true} />
      </ModalErrorBoundary>
    );
    expect(screen.getByText('Something went wrong in this panel.')).toBeInTheDocument();
  });

  it('shows Try Again button in fallback', () => {
    render(
      <ModalErrorBoundary>
        <Bomb shouldThrow={true} />
      </ModalErrorBoundary>
    );
    expect(screen.getByText('Try Again')).toBeInTheDocument();
  });

  it('resets error state when Try Again is clicked', () => {
    let shouldThrow = true;
    const { rerender } = render(
      <ModalErrorBoundary>
        <Bomb shouldThrow={shouldThrow} />
      </ModalErrorBoundary>
    );
    expect(screen.getByText('Try Again')).toBeInTheDocument();
    shouldThrow = false;
    rerender(
      <ModalErrorBoundary>
        <Bomb shouldThrow={shouldThrow} />
      </ModalErrorBoundary>
    );
    fireEvent.click(screen.getByText('Try Again'));
    expect(screen.getByText('Normal content')).toBeInTheDocument();
  });
});
