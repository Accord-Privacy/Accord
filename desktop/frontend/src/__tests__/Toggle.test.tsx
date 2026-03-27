import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Toggle } from '../components/ui/Toggle';

describe('Toggle', () => {
  it('renders toggle switch', () => {
    render(<Toggle checked={false} onChange={vi.fn()} />);
    const toggle = screen.getByRole('switch');
    expect(toggle).toBeInTheDocument();
  });

  it('renders with unchecked state', () => {
    render(<Toggle checked={false} onChange={vi.fn()} />);
    const toggle = screen.getByRole('switch');
    expect(toggle).toHaveAttribute('aria-checked', 'false');
    expect(toggle).not.toHaveClass('toggle-on');
  });

  it('renders with checked state', () => {
    render(<Toggle checked={true} onChange={vi.fn()} />);
    const toggle = screen.getByRole('switch');
    expect(toggle).toHaveAttribute('aria-checked', 'true');
    expect(toggle).toHaveClass('toggle-on');
  });

  it('renders label when provided', () => {
    render(<Toggle checked={false} onChange={vi.fn()} label="Enable feature" />);
    expect(screen.getByText('Enable feature')).toBeInTheDocument();
    expect(screen.getByText('Enable feature')).toHaveClass('toggle-label');
  });

  it('does not render label when not provided', () => {
    const { container } = render(<Toggle checked={false} onChange={vi.fn()} />);
    expect(container.querySelector('.toggle-label')).not.toBeInTheDocument();
  });

  it('renders description when provided', () => {
    render(<Toggle checked={false} onChange={vi.fn()} description="This enables the feature" />);
    expect(screen.getByText('This enables the feature')).toBeInTheDocument();
    expect(screen.getByText('This enables the feature')).toHaveClass('toggle-description');
  });

  it('does not render description when not provided', () => {
    const { container } = render(<Toggle checked={false} onChange={vi.fn()} />);
    expect(container.querySelector('.toggle-description')).not.toBeInTheDocument();
  });

  it('calls onChange with true when clicked from unchecked state', () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} />);
    fireEvent.click(screen.getByRole('switch'));
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it('calls onChange with false when clicked from checked state', () => {
    const onChange = vi.fn();
    render(<Toggle checked={true} onChange={onChange} />);
    fireEvent.click(screen.getByRole('switch'));
    expect(onChange).toHaveBeenCalledWith(false);
  });

  it('toggles on Enter key press', () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} />);
    fireEvent.keyDown(screen.getByRole('switch'), { key: 'Enter' });
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it('toggles on Space key press', () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} />);
    fireEvent.keyDown(screen.getByRole('switch'), { key: ' ' });
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it('prevents default behavior on Space key', () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} />);
    const event = new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true });
    const preventDefaultSpy = vi.spyOn(event, 'preventDefault');
    screen.getByRole('switch').dispatchEvent(event);
    expect(preventDefaultSpy).toHaveBeenCalled();
  });

  it('does not toggle on other key presses', () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} />);
    fireEvent.keyDown(screen.getByRole('switch'), { key: 'a' });
    expect(onChange).not.toHaveBeenCalled();
  });

  it('applies disabled styling when disabled', () => {
    const { container } = render(<Toggle checked={false} onChange={vi.fn()} disabled />);
    const row = container.querySelector('.toggle-row');
    expect(row).toHaveClass('toggle-disabled');
  });

  it('does not call onChange when disabled and clicked', () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} disabled />);
    fireEvent.click(screen.getByRole('switch'));
    expect(onChange).not.toHaveBeenCalled();
  });

  it('does not call onChange when disabled and Enter is pressed', () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} disabled />);
    fireEvent.keyDown(screen.getByRole('switch'), { key: 'Enter' });
    expect(onChange).not.toHaveBeenCalled();
  });

  it('sets tabIndex to -1 when disabled', () => {
    render(<Toggle checked={false} onChange={vi.fn()} disabled />);
    const toggle = screen.getByRole('switch');
    expect(toggle).toHaveAttribute('tabIndex', '-1');
  });

  it('sets tabIndex to 0 when enabled', () => {
    render(<Toggle checked={false} onChange={vi.fn()} />);
    const toggle = screen.getByRole('switch');
    expect(toggle).toHaveAttribute('tabIndex', '0');
  });

  it('applies custom className', () => {
    const { container } = render(<Toggle checked={false} onChange={vi.fn()} className="custom-toggle" />);
    const row = container.querySelector('.toggle-row');
    expect(row).toHaveClass('custom-toggle');
  });

  it('renders toggle knob', () => {
    const { container } = render(<Toggle checked={false} onChange={vi.fn()} />);
    expect(container.querySelector('.toggle-knob')).toBeInTheDocument();
  });
});
