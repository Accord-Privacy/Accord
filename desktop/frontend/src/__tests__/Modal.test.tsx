import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Modal } from '../components/ui/Modal';

describe('Modal', () => {
  it('renders nothing when isOpen is false', () => {
    const { container } = render(
      <Modal isOpen={false} onClose={vi.fn()}>
        <div>Modal content</div>
      </Modal>
    );
    expect(container.querySelector('.modal-overlay')).not.toBeInTheDocument();
  });

  it('renders modal when isOpen is true', () => {
    render(
      <Modal isOpen={true} onClose={vi.fn()}>
        <div>Modal content</div>
      </Modal>
    );
    expect(screen.getByText('Modal content')).toBeInTheDocument();
  });

  it('renders overlay when open', () => {
    const { container } = render(
      <Modal isOpen={true} onClose={vi.fn()}>
        <div>Content</div>
      </Modal>
    );
    expect(container.querySelector('.modal-overlay')).toBeInTheDocument();
  });

  it('renders modal card when open', () => {
    const { container } = render(
      <Modal isOpen={true} onClose={vi.fn()}>
        <div>Content</div>
      </Modal>
    );
    expect(container.querySelector('.modal-card')).toBeInTheDocument();
  });

  it('renders title when provided', () => {
    render(
      <Modal isOpen={true} onClose={vi.fn()} title="Confirm Action">
        <div>Content</div>
      </Modal>
    );
    expect(screen.getByText('Confirm Action')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3 })).toHaveTextContent('Confirm Action');
  });

  it('does not render title when not provided', () => {
    const { container } = render(
      <Modal isOpen={true} onClose={vi.fn()}>
        <div>Content</div>
      </Modal>
    );
    expect(container.querySelector('h3')).not.toBeInTheDocument();
  });

  it('renders description when provided', () => {
    render(
      <Modal isOpen={true} onClose={vi.fn()} description="Are you sure?">
        <div>Content</div>
      </Modal>
    );
    expect(screen.getByText('Are you sure?')).toBeInTheDocument();
  });

  it('does not render description when not provided', () => {
    const { container } = render(
      <Modal isOpen={true} onClose={vi.fn()}>
        <div>Content</div>
      </Modal>
    );
    const paragraphs = container.querySelectorAll('p');
    expect(paragraphs.length).toBe(0);
  });

  it('renders children content', () => {
    render(
      <Modal isOpen={true} onClose={vi.fn()}>
        <p>This is the modal body</p>
      </Modal>
    );
    expect(screen.getByText('This is the modal body')).toBeInTheDocument();
  });

  it('renders actions when provided', () => {
    render(
      <Modal isOpen={true} onClose={vi.fn()} actions={<button>OK</button>}>
        <div>Content</div>
      </Modal>
    );
    expect(screen.getByText('OK')).toBeInTheDocument();
  });

  it('applies default maxWidth of 440px', () => {
    const { container } = render(
      <Modal isOpen={true} onClose={vi.fn()}>
        <div>Content</div>
      </Modal>
    );
    const card = container.querySelector('.modal-card') as HTMLElement;
    expect(card.style.maxWidth).toBe('440px');
  });

  it('applies custom maxWidth', () => {
    const { container } = render(
      <Modal isOpen={true} onClose={vi.fn()} maxWidth={600}>
        <div>Content</div>
      </Modal>
    );
    const card = container.querySelector('.modal-card') as HTMLElement;
    expect(card.style.maxWidth).toBe('600px');
  });

  it('calls onClose when Escape key is pressed', () => {
    const onClose = vi.fn();
    render(
      <Modal isOpen={true} onClose={onClose}>
        <div>Content</div>
      </Modal>
    );
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('does not call onClose for other keys', () => {
    const onClose = vi.fn();
    render(
      <Modal isOpen={true} onClose={onClose}>
        <div>Content</div>
      </Modal>
    );
    fireEvent.keyDown(window, { key: 'Enter' });
    expect(onClose).not.toHaveBeenCalled();
  });

  it('calls onClose when clicking overlay background', () => {
    const onClose = vi.fn();
    const { container } = render(
      <Modal isOpen={true} onClose={onClose}>
        <div>Content</div>
      </Modal>
    );
    const overlay = container.querySelector('.modal-overlay');
    if (overlay) {
      fireEvent.click(overlay);
    }
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('does not call onClose when clicking modal card content', () => {
    const onClose = vi.fn();
    render(
      <Modal isOpen={true} onClose={onClose}>
        <div>Content</div>
      </Modal>
    );
    fireEvent.click(screen.getByText('Content'));
    expect(onClose).not.toHaveBeenCalled();
  });
});
