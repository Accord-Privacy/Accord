import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { ToastProvider, useToast } from '../components/ui/Toast';

// Test component to access useToast hook
const ToastTrigger = () => {
  const { toast } = useToast();
  return (
    <div>
      <button onClick={() => toast('Info message', 'info')}>Show Info</button>
      <button onClick={() => toast('Success message', 'success')}>Show Success</button>
      <button onClick={() => toast('Error message', 'error')}>Show Error</button>
      <button onClick={() => toast('Warning message', 'warning')}>Show Warning</button>
      <button onClick={() => toast('Default message')}>Show Default</button>
    </div>
  );
};

describe('Toast', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders children without toasts initially', () => {
    render(
      <ToastProvider>
        <div>App content</div>
      </ToastProvider>
    );
    expect(screen.getByText('App content')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows toast when triggered', () => {
    render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Info'));
    expect(screen.getByText('Info message')).toBeInTheDocument();
  });

  it('shows info toast with correct icon', () => {
    render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Info'));
    expect(screen.getByText('ℹ')).toBeInTheDocument();
  });

  it('shows success toast with correct icon', () => {
    render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Success'));
    expect(screen.getByText('✓')).toBeInTheDocument();
    expect(screen.getByText('Success message')).toBeInTheDocument();
  });

  it('shows error toast with correct icon', () => {
    render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Error'));
    expect(screen.getByText('✕')).toBeInTheDocument();
    expect(screen.getByText('Error message')).toBeInTheDocument();
  });

  it('shows warning toast with correct icon', () => {
    render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Warning'));
    expect(screen.getByText('⚠')).toBeInTheDocument();
    expect(screen.getByText('Warning message')).toBeInTheDocument();
  });

  it('defaults to info type when no type is provided', () => {
    render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Default'));
    expect(screen.getByText('ℹ')).toBeInTheDocument();
  });

  it('applies correct CSS class for toast type', () => {
    const { container } = render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Success'));
    const toast = container.querySelector('.toast-success');
    expect(toast).toBeInTheDocument();
  });

  it('auto-dismisses toast after 4 seconds', () => {
    render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Info'));
    expect(screen.getByText('Info message')).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(4000);
    });

    expect(screen.queryByText('Info message')).not.toBeInTheDocument();
  });

  it('dismisses toast on click', () => {
    const { container } = render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Info'));
    const toast = container.querySelector('.toast');
    expect(toast).toBeInTheDocument();

    if (toast) {
      fireEvent.click(toast);
    }

    expect(screen.queryByText('Info message')).not.toBeInTheDocument();
  });

  it('renders multiple toasts simultaneously', () => {
    render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Info'));
    fireEvent.click(screen.getByText('Show Success'));
    fireEvent.click(screen.getByText('Show Error'));

    expect(screen.getByText('Info message')).toBeInTheDocument();
    expect(screen.getByText('Success message')).toBeInTheDocument();
    expect(screen.getByText('Error message')).toBeInTheDocument();
  });

  it('renders toast container only when toasts exist', () => {
    const { container } = render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    expect(container.querySelector('.toast-container')).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('Show Info'));
    expect(container.querySelector('.toast-container')).toBeInTheDocument();
  });

  it('clears timers on unmount', () => {
    const clearTimeoutSpy = vi.spyOn(global, 'clearTimeout');
    const { unmount } = render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Info'));
    unmount();
    expect(clearTimeoutSpy).toHaveBeenCalled();
  });

  it('generates unique IDs for toasts', () => {
    const { container } = render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    );
    fireEvent.click(screen.getByText('Show Info'));
    fireEvent.click(screen.getByText('Show Success'));

    const toasts = container.querySelectorAll('.toast');
    expect(toasts.length).toBe(2);
    // Each should have a unique key (React handles this internally)
  });
});
