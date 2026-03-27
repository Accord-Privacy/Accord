import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Badge } from '../components/ui/Badge';

describe('Badge', () => {
  it('renders inline badge with default variant', () => {
    render(<Badge>New</Badge>);
    const badge = screen.getByText('New');
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveClass('badge');
    expect(badge).toHaveClass('badge-default');
  });

  it('renders with accent variant', () => {
    render(<Badge variant="accent">Accent</Badge>);
    const badge = screen.getByText('Accent');
    expect(badge).toHaveClass('badge-accent');
  });

  it('renders with green variant', () => {
    render(<Badge variant="green">Success</Badge>);
    const badge = screen.getByText('Success');
    expect(badge).toHaveClass('badge-green');
  });

  it('renders with red variant', () => {
    render(<Badge variant="red">Error</Badge>);
    const badge = screen.getByText('Error');
    expect(badge).toHaveClass('badge-red');
  });

  it('renders with yellow variant', () => {
    render(<Badge variant="yellow">Warning</Badge>);
    const badge = screen.getByText('Warning');
    expect(badge).toHaveClass('badge-yellow');
  });

  it('renders count-only badge when count is provided without children', () => {
    const { container } = render(<Badge count={5} children={undefined} />);
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(container.querySelector('.badge-wrapper')).not.toBeInTheDocument();
  });

  it('displays "99+" for counts over 99 in count-only mode', () => {
    render(<Badge count={150} children={undefined} />);
    expect(screen.getByText('99+')).toBeInTheDocument();
  });

  it('displays exact count of 99 in count-only mode', () => {
    render(<Badge count={99} children={undefined} />);
    expect(screen.getByText('99')).toBeInTheDocument();
  });

  it('renders dot badge on children', () => {
    const { container } = render(
      <Badge dot>
        <div>Content</div>
      </Badge>
    );
    expect(screen.getByText('Content')).toBeInTheDocument();
    expect(container.querySelector('.badge-wrapper')).toBeInTheDocument();
    expect(container.querySelector('.badge-dot')).toBeInTheDocument();
  });

  it('renders count overlay on children', () => {
    const { container } = render(
      <Badge count={3}>
        <div>Icon</div>
      </Badge>
    );
    expect(screen.getByText('Icon')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(container.querySelector('.badge-overlay')).toBeInTheDocument();
  });

  it('displays "99+" for counts over 99 in overlay mode', () => {
    render(
      <Badge count={200}>
        <div>Icon</div>
      </Badge>
    );
    expect(screen.getByText('99+')).toBeInTheDocument();
  });

  it('does not render count overlay when count is 0', () => {
    const { container } = render(
      <Badge count={0}>
        <div>Icon</div>
      </Badge>
    );
    expect(container.querySelector('.badge-overlay')).not.toBeInTheDocument();
  });

  it('applies className to count-only badge', () => {
    render(<Badge count={5} className="custom-badge" children={undefined} />);
    const badge = screen.getByText('5');
    expect(badge).toHaveClass('custom-badge');
  });

  it('applies className to wrapper when using dot/count', () => {
    const { container } = render(
      <Badge dot className="custom-wrapper">
        <div>Content</div>
      </Badge>
    );
    const wrapper = container.querySelector('.badge-wrapper');
    expect(wrapper).toHaveClass('custom-wrapper');
  });

  it('applies className to inline badge', () => {
    render(<Badge className="custom-inline">Inline</Badge>);
    const badge = screen.getByText('Inline');
    expect(badge).toHaveClass('custom-inline');
  });

  it('renders count variant in count-only mode', () => {
    render(<Badge count={10} variant="red" children={undefined} />);
    const badge = screen.getByText('10');
    expect(badge).toHaveClass('badge-red');
  });

  it('renders count variant in overlay mode', () => {
    render(
      <Badge count={5} variant="green">
        <div>Icon</div>
      </Badge>
    );
    const badge = screen.getByText('5');
    expect(badge).toHaveClass('badge-green');
  });
});
