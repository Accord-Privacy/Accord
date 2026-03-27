import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { Tooltip } from '../components/ui/Tooltip';

describe('Tooltip', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders children without tooltip initially', () => {
    render(
      <Tooltip content="Helpful hint">
        <button>Hover me</button>
      </Tooltip>
    );
    expect(screen.getByText('Hover me')).toBeInTheDocument();
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
  });

  it('shows tooltip after mouse enter with delay', () => {
    render(
      <Tooltip content="Helpful hint">
        <button>Hover me</button>
      </Tooltip>
    );
    const wrapper = screen.getByText('Hover me').parentElement;
    if (wrapper) {
      fireEvent.mouseEnter(wrapper);
    }

    // Should not show immediately
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();

    // Should show after default delay (400ms)
    act(() => {
      vi.advanceTimersByTime(400);
    });
    expect(screen.getByRole('tooltip')).toHaveTextContent('Helpful hint');
  });

  it('hides tooltip on mouse leave', () => {
    render(
      <Tooltip content="Helpful hint">
        <button>Hover me</button>
      </Tooltip>
    );
    const wrapper = screen.getByText('Hover me').parentElement;
    if (wrapper) {
      fireEvent.mouseEnter(wrapper);
      act(() => {
        vi.advanceTimersByTime(400);
      });
      expect(screen.getByRole('tooltip')).toBeInTheDocument();

      fireEvent.mouseLeave(wrapper);
      expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
    }
  });

  it('respects custom delay', () => {
    render(
      <Tooltip content="Helpful hint" delay={1000}>
        <button>Hover me</button>
      </Tooltip>
    );
    const wrapper = screen.getByText('Hover me').parentElement;
    if (wrapper) {
      fireEvent.mouseEnter(wrapper);
    }

    // Should not show at 500ms
    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();

    // Should show after 1000ms
    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(screen.getByRole('tooltip')).toBeInTheDocument();
  });

  it('renders with top position by default', () => {
    render(
      <Tooltip content="Helpful hint">
        <button>Hover me</button>
      </Tooltip>
    );
    const wrapper = screen.getByText('Hover me').parentElement;
    if (wrapper) {
      fireEvent.mouseEnter(wrapper);
      act(() => {
        vi.advanceTimersByTime(400);
      });
      expect(screen.getByRole('tooltip')).toHaveClass('tooltip-top');
    }
  });

  it('renders with bottom position', () => {
    render(
      <Tooltip content="Helpful hint" position="bottom">
        <button>Hover me</button>
      </Tooltip>
    );
    const wrapper = screen.getByText('Hover me').parentElement;
    if (wrapper) {
      fireEvent.mouseEnter(wrapper);
      act(() => {
        vi.advanceTimersByTime(400);
      });
      expect(screen.getByRole('tooltip')).toHaveClass('tooltip-bottom');
    }
  });

  it('renders with left position', () => {
    render(
      <Tooltip content="Helpful hint" position="left">
        <button>Hover me</button>
      </Tooltip>
    );
    const wrapper = screen.getByText('Hover me').parentElement;
    if (wrapper) {
      fireEvent.mouseEnter(wrapper);
      act(() => {
        vi.advanceTimersByTime(400);
      });
      expect(screen.getByRole('tooltip')).toHaveClass('tooltip-left');
    }
  });

  it('renders with right position', () => {
    render(
      <Tooltip content="Helpful hint" position="right">
        <button>Hover me</button>
      </Tooltip>
    );
    const wrapper = screen.getByText('Hover me').parentElement;
    if (wrapper) {
      fireEvent.mouseEnter(wrapper);
      act(() => {
        vi.advanceTimersByTime(400);
      });
      expect(screen.getByRole('tooltip')).toHaveClass('tooltip-right');
    }
  });

  it('cancels tooltip on mouse leave before delay completes', () => {
    render(
      <Tooltip content="Helpful hint">
        <button>Hover me</button>
      </Tooltip>
    );
    const wrapper = screen.getByText('Hover me').parentElement;
    if (wrapper) {
      fireEvent.mouseEnter(wrapper);
      act(() => {
        vi.advanceTimersByTime(200);
      });

      fireEvent.mouseLeave(wrapper);
      act(() => {
        vi.advanceTimersByTime(300);
      });

      expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
    }
  });

  it('renders tooltip content correctly', () => {
    render(
      <Tooltip content="This is a detailed tooltip message">
        <button>Hover me</button>
      </Tooltip>
    );
    const wrapper = screen.getByText('Hover me').parentElement;
    if (wrapper) {
      fireEvent.mouseEnter(wrapper);
      act(() => {
        vi.advanceTimersByTime(400);
      });
      expect(screen.getByRole('tooltip')).toHaveTextContent('This is a detailed tooltip message');
    }
  });

  it('applies tooltip wrapper class', () => {
    const { container } = render(
      <Tooltip content="Hint">
        <button>Hover me</button>
      </Tooltip>
    );
    expect(container.querySelector('.tooltip-wrapper')).toBeInTheDocument();
  });

  it('handles rapid mouse enter/leave cycles', () => {
    render(
      <Tooltip content="Helpful hint">
        <button>Hover me</button>
      </Tooltip>
    );
    const wrapper = screen.getByText('Hover me').parentElement;
    if (wrapper) {
      // Enter and leave quickly multiple times
      fireEvent.mouseEnter(wrapper);
      act(() => {
        vi.advanceTimersByTime(100);
      });
      fireEvent.mouseLeave(wrapper);

      fireEvent.mouseEnter(wrapper);
      act(() => {
        vi.advanceTimersByTime(100);
      });
      fireEvent.mouseLeave(wrapper);

      fireEvent.mouseEnter(wrapper);
      act(() => {
        vi.advanceTimersByTime(400);
      });

      // Only the last enter should result in showing tooltip
      expect(screen.getByRole('tooltip')).toBeInTheDocument();
    }
  });

  it('renders with zero delay', () => {
    render(
      <Tooltip content="Instant tooltip" delay={0}>
        <button>Hover me</button>
      </Tooltip>
    );
    const wrapper = screen.getByText('Hover me').parentElement;
    if (wrapper) {
      fireEvent.mouseEnter(wrapper);
      act(() => {
        vi.advanceTimersByTime(0);
      });
      expect(screen.getByRole('tooltip')).toBeInTheDocument();
    }
  });
});
