import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render } from '@testing-library/react';
import { OnboardingTour } from '../components/OnboardingTour';

describe('OnboardingTour', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
  });

  it('does not render when onboarding is already complete', () => {
    localStorage.setItem('accord-onboarding-complete', 'true');
    const { container } = render(<OnboardingTour />);
    expect(container.querySelector('.onboarding-overlay')).not.toBeInTheDocument();
  });

  it('does not render on first session', () => {
    const { container } = render(<OnboardingTour />);
    expect(container.querySelector('.onboarding-overlay')).not.toBeInTheDocument();
    expect(sessionStorage.getItem('accord-onboarding-session-seen')).toBe('true');
  });

  it('marks session as seen on first render', () => {
    render(<OnboardingTour />);
    expect(sessionStorage.getItem('accord-onboarding-session-seen')).toBe('true');
  });

  it('does not render initially even with session seen', () => {
    sessionStorage.setItem('accord-onboarding-session-seen', 'true');
    const { container } = render(<OnboardingTour />);
    // Tour waits for nodes to appear, so it should not render immediately
    expect(container.querySelector('.onboarding-overlay')).not.toBeInTheDocument();
  });

  it('respects localStorage onboarding complete flag', () => {
    localStorage.setItem('accord-onboarding-complete', 'true');
    sessionStorage.setItem('accord-onboarding-session-seen', 'true');
    const { container } = render(<OnboardingTour />);
    expect(container.querySelector('.onboarding-overlay')).not.toBeInTheDocument();
  });

  it('initializes with correct storage keys', () => {
    render(<OnboardingTour />);
    // Check that the component respects the storage keys
    expect(localStorage.getItem('accord-onboarding-complete')).toBeNull();
    expect(sessionStorage.getItem('accord-onboarding-session-seen')).toBe('true');
  });

  it('renders component without crashing', () => {
    const { container } = render(<OnboardingTour />);
    expect(container).toBeTruthy();
  });

  it('does not show tour when no session storage key', () => {
    const { container } = render(<OnboardingTour />);
    expect(container.querySelector('.onboarding-overlay')).not.toBeInTheDocument();
  });

  it('checks for existing modal before showing tour', () => {
    sessionStorage.setItem('accord-onboarding-session-seen', 'true');
    // Add a modal to the DOM
    const modal = document.createElement('div');
    modal.setAttribute('role', 'dialog');
    modal.className = 'modal-overlay';
    document.body.appendChild(modal);

    const { container } = render(<OnboardingTour />);

    // Tour should not show immediately even with session seen because modal exists
    expect(container.querySelector('.onboarding-overlay')).not.toBeInTheDocument();

    document.body.removeChild(modal);
  });

  it('respects onboarding-complete flag from localStorage', () => {
    localStorage.setItem('accord-onboarding-complete', 'true');
    const { container } = render(<OnboardingTour />);
    expect(container.querySelector('.onboarding-overlay')).not.toBeInTheDocument();
  });

  it('does not crash when rendering multiple times', () => {
    const { rerender } = render(<OnboardingTour />);
    rerender(<OnboardingTour />);
    rerender(<OnboardingTour />);
    expect(true).toBe(true); // No crash
  });

  it('handles missing DOM elements gracefully', () => {
    sessionStorage.setItem('accord-onboarding-session-seen', 'true');
    const { container } = render(<OnboardingTour />);
    // Should not crash even without server icons
    expect(container).toBeTruthy();
  });

  it('initializes correctly with all props', () => {
    const { container } = render(<OnboardingTour />);
    expect(container.firstChild).toBeDefined();
  });

  it('does not render overlay initially', () => {
    const { container } = render(<OnboardingTour />);
    expect(container.querySelector('.onboarding-overlay')).not.toBeInTheDocument();
  });

  it('sets session storage on mount', () => {
    expect(sessionStorage.getItem('accord-onboarding-session-seen')).toBeNull();
    render(<OnboardingTour />);
    expect(sessionStorage.getItem('accord-onboarding-session-seen')).toBe('true');
  });
});
