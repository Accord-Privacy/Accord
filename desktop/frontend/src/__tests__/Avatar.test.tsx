import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Avatar } from '../components/ui/Avatar';
import { api } from '../api';

vi.mock('../api', () => ({
  api: {
    getUserAvatarUrl: vi.fn((userId: string) => `https://api.example.com/avatar/${userId}`),
  },
}));

describe('Avatar', () => {
  it('renders fallback with initial when no src or userId', () => {
    const { container } = render(<Avatar name="John Doe" />);
    const fallback = container.querySelector('.avatar-fallback');
    expect(fallback).toBeInTheDocument();
    expect(fallback).toHaveTextContent('J');
  });

  it('uses first character of name as initial', () => {
    const { container } = render(<Avatar name="Alice" />);
    const fallback = container.querySelector('.avatar-fallback');
    expect(fallback).toHaveTextContent('A');
  });

  it('defaults to "?" when name is empty', () => {
    const { container } = render(<Avatar name="" />);
    const fallback = container.querySelector('.avatar-fallback');
    expect(fallback).toHaveTextContent('?');
  });

  it('defaults to "?" when name is undefined', () => {
    const { container } = render(<Avatar />);
    const fallback = container.querySelector('.avatar-fallback');
    expect(fallback).toHaveTextContent('?');
  });

  it('renders image when src is provided', () => {
    render(<Avatar src="https://example.com/avatar.png" name="Test" />);
    const img = screen.getByRole('img');
    expect(img).toBeInTheDocument();
    expect(img).toHaveAttribute('src', 'https://example.com/avatar.png');
  });

  it('uses api.getUserAvatarUrl when userId is provided', () => {
    render(<Avatar userId="user123" name="Test" />);
    const img = screen.getByRole('img');
    expect(img).toHaveAttribute('src', 'https://api.example.com/avatar/user123');
    expect(api.getUserAvatarUrl).toHaveBeenCalledWith('user123');
  });

  it('prefers src over userId when both are provided', () => {
    render(<Avatar src="https://example.com/custom.png" userId="user123" name="Test" />);
    const img = screen.getByRole('img');
    expect(img).toHaveAttribute('src', 'https://example.com/custom.png');
  });

  it('applies default size of 40px', () => {
    const { container } = render(<Avatar name="Test" />);
    const fallback = container.querySelector('.avatar-fallback') as HTMLElement;
    expect(fallback.style.width).toBe('40px');
    expect(fallback.style.height).toBe('40px');
  });

  it('respects custom size prop', () => {
    const { container } = render(<Avatar name="Test" size={64} />);
    const fallback = container.querySelector('.avatar-fallback') as HTMLElement;
    expect(fallback.style.width).toBe('64px');
    expect(fallback.style.height).toBe('64px');
  });

  it('applies className to fallback', () => {
    const { container } = render(<Avatar name="Test" className="custom-class" />);
    const fallback = container.querySelector('.avatar-fallback');
    expect(fallback).toHaveClass('custom-class');
  });

  it('applies className to image', () => {
    render(<Avatar src="https://example.com/avatar.png" name="Test" className="custom-img" />);
    const img = screen.getByRole('img');
    expect(img).toHaveClass('custom-img');
  });

  it('applies custom style to fallback', () => {
    const { container } = render(<Avatar name="Test" style={{ border: '2px solid red' }} />);
    const fallback = container.querySelector('.avatar-fallback') as HTMLElement;
    expect(fallback.style.border).toBe('2px solid red');
  });

  it('falls back to initial on image error', () => {
    const { container } = render(<Avatar src="https://example.com/broken.png" name="Error Test" />);
    const img = screen.getByRole('img');

    // Trigger error
    fireEvent.error(img);

    // Should now show fallback
    const fallback = container.querySelector('.avatar-fallback');
    expect(fallback).toBeInTheDocument();
    expect(fallback).toHaveTextContent('E');
  });

  it('removes src attribute on error', () => {
    render(<Avatar src="https://example.com/broken.png" name="Test" />);
    const img = screen.getByRole('img');

    expect(img).toHaveAttribute('src');
    fireEvent.error(img);
    expect(img).not.toHaveAttribute('src');
  });

  it('uses uppercased initial in fallback', () => {
    const { container } = render(<Avatar name="alice" />);
    const fallback = container.querySelector('.avatar-fallback');
    expect(fallback).toHaveTextContent('A');
  });
});
