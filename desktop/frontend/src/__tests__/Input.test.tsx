import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Input, TextArea } from '../components/ui/Input';
import { createRef } from 'react';

describe('Input', () => {
  it('renders input element', () => {
    render(<Input />);
    const input = screen.getByRole('textbox');
    expect(input).toBeInTheDocument();
  });

  it('renders with label', () => {
    render(<Input label="Username" />);
    expect(screen.getByLabelText('Username')).toBeInTheDocument();
    expect(screen.getByText('Username')).toHaveClass('form-label');
  });

  it('auto-generates id from label', () => {
    render(<Input label="Email Address" />);
    const input = screen.getByLabelText('Email Address');
    expect(input).toHaveAttribute('id', 'input-email-address');
  });

  it('uses custom id when provided', () => {
    render(<Input label="Email" id="custom-email" />);
    const input = screen.getByLabelText('Email');
    expect(input).toHaveAttribute('id', 'custom-email');
  });

  it('displays error message', () => {
    render(<Input error="This field is required" />);
    expect(screen.getByText('This field is required')).toBeInTheDocument();
    expect(screen.getByText('This field is required')).toHaveClass('form-error');
  });

  it('applies error class to input when error is present', () => {
    render(<Input error="Error" />);
    const input = screen.getByRole('textbox');
    expect(input).toHaveClass('form-input-error');
  });

  it('displays hint message', () => {
    render(<Input hint="Enter your email address" />);
    expect(screen.getByText('Enter your email address')).toBeInTheDocument();
    expect(screen.getByText('Enter your email address')).toHaveClass('form-hint');
  });

  it('does not display hint when error is present', () => {
    render(<Input hint="Hint text" error="Error text" />);
    expect(screen.queryByText('Hint text')).not.toBeInTheDocument();
    expect(screen.getByText('Error text')).toBeInTheDocument();
  });

  it('renders with md size by default', () => {
    render(<Input />);
    const input = screen.getByRole('textbox');
    expect(input).toHaveClass('form-input');
    expect(input).not.toHaveClass('form-input-sm');
    expect(input).not.toHaveClass('form-input-lg');
  });

  it('renders with sm size', () => {
    render(<Input inputSize="sm" />);
    const input = screen.getByRole('textbox');
    expect(input).toHaveClass('form-input-sm');
  });

  it('renders with lg size', () => {
    render(<Input inputSize="lg" />);
    const input = screen.getByRole('textbox');
    expect(input).toHaveClass('form-input-lg');
  });

  it('applies fullWidth class by default', () => {
    render(<Input />);
    const input = screen.getByRole('textbox');
    expect(input).toHaveClass('form-input-full');
  });

  it('does not apply fullWidth class when fullWidth is false', () => {
    render(<Input fullWidth={false} />);
    const input = screen.getByRole('textbox');
    expect(input).not.toHaveClass('form-input-full');
  });

  it('applies custom className', () => {
    render(<Input className="custom-input" />);
    const input = screen.getByRole('textbox');
    expect(input).toHaveClass('custom-input');
  });

  it('forwards HTML input attributes', () => {
    render(<Input placeholder="Enter text" type="email" disabled />);
    const input = screen.getByRole('textbox');
    expect(input).toHaveAttribute('placeholder', 'Enter text');
    expect(input).toHaveAttribute('type', 'email');
    expect(input).toBeDisabled();
  });

  it('handles onChange events', () => {
    const handleChange = vi.fn();
    render(<Input onChange={handleChange} />);
    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: 'test' } });
    expect(handleChange).toHaveBeenCalled();
  });

  it('forwards ref to input element', () => {
    const ref = createRef<HTMLInputElement>();
    render(<Input ref={ref} />);
    expect(ref.current).toBeInstanceOf(HTMLInputElement);
  });
});

describe('TextArea', () => {
  it('renders textarea element', () => {
    render(<TextArea />);
    const textarea = screen.getByRole('textbox');
    expect(textarea.tagName).toBe('TEXTAREA');
  });

  it('renders with label', () => {
    render(<TextArea label="Message" />);
    expect(screen.getByLabelText('Message')).toBeInTheDocument();
    expect(screen.getByText('Message')).toHaveClass('form-label');
  });

  it('auto-generates id from label', () => {
    render(<TextArea label="Bio Text" />);
    const textarea = screen.getByLabelText('Bio Text');
    expect(textarea).toHaveAttribute('id', 'textarea-bio-text');
  });

  it('uses custom id when provided', () => {
    render(<TextArea label="Bio" id="custom-bio" />);
    const textarea = screen.getByLabelText('Bio');
    expect(textarea).toHaveAttribute('id', 'custom-bio');
  });

  it('displays error message', () => {
    render(<TextArea error="Too long" />);
    expect(screen.getByText('Too long')).toBeInTheDocument();
    expect(screen.getByText('Too long')).toHaveClass('form-error');
  });

  it('applies error class to textarea when error is present', () => {
    render(<TextArea error="Error" />);
    const textarea = screen.getByRole('textbox');
    expect(textarea).toHaveClass('form-input-error');
  });

  it('displays hint message', () => {
    render(<TextArea hint="Maximum 500 characters" />);
    expect(screen.getByText('Maximum 500 characters')).toBeInTheDocument();
  });

  it('does not display hint when error is present', () => {
    render(<TextArea hint="Hint" error="Error" />);
    expect(screen.queryByText('Hint')).not.toBeInTheDocument();
    expect(screen.getByText('Error')).toBeInTheDocument();
  });

  it('applies fullWidth class by default', () => {
    render(<TextArea />);
    const textarea = screen.getByRole('textbox');
    expect(textarea).toHaveClass('form-input-full');
  });

  it('applies custom className', () => {
    render(<TextArea className="custom-textarea" />);
    const textarea = screen.getByRole('textbox');
    expect(textarea).toHaveClass('custom-textarea');
    expect(textarea).toHaveClass('form-textarea');
  });

  it('forwards HTML textarea attributes', () => {
    render(<TextArea placeholder="Type here" rows={5} disabled />);
    const textarea = screen.getByRole('textbox');
    expect(textarea).toHaveAttribute('placeholder', 'Type here');
    expect(textarea).toHaveAttribute('rows', '5');
    expect(textarea).toBeDisabled();
  });

  it('forwards ref to textarea element', () => {
    const ref = createRef<HTMLTextAreaElement>();
    render(<TextArea ref={ref} />);
    expect(ref.current).toBeInstanceOf(HTMLTextAreaElement);
  });
});
