import React, { useState, useEffect, useCallback } from "react";
import "../styles/onboarding.css";

interface TourStep {
  title: string;
  description: string;
  targetSelector: string;
  position: "right" | "left" | "bottom" | "top";
}

const TOUR_STEPS: TourStep[] = [
  {
    title: "Welcome to Accord!",
    description: "A privacy-first messaging platform. Your messages are encrypted end-to-end — no one can read them but you and the people you're talking to.",
    targetSelector: ".app",
    position: "bottom",
  },
  {
    title: "Your Nodes",
    description: "These are your Nodes (like Discord servers). Each node is a community you belong to. Click one to enter.",
    targetSelector: ".server-list",
    position: "right",
  },
  {
    title: "Channels",
    description: "Chat in channels, organized by topic. Text and voice channels keep conversations focused.",
    targetSelector: ".channel-sidebar",
    position: "right",
  },
  {
    title: "End-to-End Encrypted",
    description: "Messages are end-to-end encrypted. Type here to send a message — only the intended recipients can decrypt it.",
    targetSelector: ".message-input-container",
    position: "top",
  },
  {
    title: "Settings",
    description: "Customize your experience in Settings — change your theme, display name, notification preferences, and more.",
    targetSelector: '.voice-ctrl-btn[title*="Settings"]',
    position: "top",
  },
];

const STORAGE_KEY = "accord-onboarding-complete";

export function OnboardingTour() {
  const [currentStep, setCurrentStep] = useState(0);
  const [visible, setVisible] = useState(false);
  const [spotlightRect, setSpotlightRect] = useState<DOMRect | null>(null);

  useEffect(() => {
    if (localStorage.getItem(STORAGE_KEY)) return;
    // Don't show tour on the very first session (setup wizard was just completed).
    // Mark this session, then show tour on next login.
    const sessionKey = "accord-onboarding-session-seen";
    if (!sessionStorage.getItem(sessionKey)) {
      sessionStorage.setItem(sessionKey, "true");
      return;
    }
    // Don't show tour if user has no nodes yet (Join/Create Node modal would overlap)
    const nodesRaw = localStorage.getItem("accord-nodes") || localStorage.getItem("nodes");
    const serverListEl = document.querySelector(".server-list .server-icon:not(.add-server)");
    if (!serverListEl && !nodesRaw) {
      // No nodes visible — wait and re-check via interval
      const interval = setInterval(() => {
        const hasNode = document.querySelector(".server-list .server-icon:not(.add-server)");
        const hasModal = document.querySelector(".modal-overlay, .modal-backdrop, [role='dialog']:not(.onboarding-overlay)");
        if (hasNode && !hasModal) {
          clearInterval(interval);
          setVisible(true);
        }
      }, 1000);
      return () => clearInterval(interval);
    }
    // Small delay so the main UI renders first
    const timer = setTimeout(() => setVisible(true), 600);
    return () => clearTimeout(timer);
  }, []);

  const updateSpotlight = useCallback(() => {
    const step = TOUR_STEPS[currentStep];
    if (!step) return;
    // Welcome step — no spotlight
    if (currentStep === 0) {
      setSpotlightRect(null);
      return;
    }
    const el = document.querySelector(step.targetSelector);
    if (el) {
      setSpotlightRect(el.getBoundingClientRect());
    } else {
      setSpotlightRect(null);
    }
  }, [currentStep]);

  useEffect(() => {
    if (!visible) return;
    updateSpotlight();
    window.addEventListener("resize", updateSpotlight);
    return () => window.removeEventListener("resize", updateSpotlight);
  }, [visible, updateSpotlight]);

  const dismiss = useCallback(() => {
    setVisible(false);
    localStorage.setItem(STORAGE_KEY, "true");
  }, []);

  const next = useCallback(() => {
    if (currentStep >= TOUR_STEPS.length - 1) {
      dismiss();
    } else {
      setCurrentStep((s) => s + 1);
    }
  }, [currentStep, dismiss]);

  const prev = useCallback(() => {
    setCurrentStep((s) => Math.max(0, s - 1));
  }, []);

  if (!visible) return null;

  const step = TOUR_STEPS[currentStep];
  const isWelcome = currentStep === 0;
  const isLast = currentStep === TOUR_STEPS.length - 1;
  const pad = 8;

  // Compute tooltip position
  let tooltipStyle: React.CSSProperties = {};
  if (isWelcome || !spotlightRect) {
    tooltipStyle = { top: "50%", left: "50%", transform: "translate(-50%, -50%)" };
  } else {
    const r = spotlightRect;
    switch (step.position) {
      case "right":
        tooltipStyle = { top: r.top + r.height / 2, left: r.right + pad + 16, transform: "translateY(-50%)" };
        break;
      case "left":
        tooltipStyle = { top: r.top + r.height / 2, right: window.innerWidth - r.left + pad + 16, transform: "translateY(-50%)" };
        break;
      case "top":
        tooltipStyle = { bottom: window.innerHeight - r.top + pad + 16, left: r.left + r.width / 2, transform: "translateX(-50%)" };
        break;
      case "bottom":
        tooltipStyle = { top: r.bottom + pad + 16, left: r.left + r.width / 2, transform: "translateX(-50%)" };
        break;
    }
  }

  return (
    <div className="onboarding-overlay" aria-modal="true" role="dialog" aria-label="Onboarding tour">
      {/* Dark overlay with spotlight cutout */}
      <svg className="onboarding-backdrop" width="100%" height="100%">
        <defs>
          <mask id="onboarding-mask">
            <rect x="0" y="0" width="100%" height="100%" fill="white" />
            {spotlightRect && (
              <rect
                x={spotlightRect.left - pad}
                y={spotlightRect.top - pad}
                width={spotlightRect.width + pad * 2}
                height={spotlightRect.height + pad * 2}
                rx="8"
                fill="black"
              />
            )}
          </mask>
        </defs>
        <rect x="0" y="0" width="100%" height="100%" fill="rgba(0,0,0,0.7)" mask="url(#onboarding-mask)" />
      </svg>

      {/* Spotlight border */}
      {spotlightRect && (
        <div
          className="onboarding-spotlight-border"
          style={{
            top: spotlightRect.top - pad,
            left: spotlightRect.left - pad,
            width: spotlightRect.width + pad * 2,
            height: spotlightRect.height + pad * 2,
          }}
        />
      )}

      {/* Tooltip card */}
      <div className="onboarding-tooltip" style={tooltipStyle}>
        <h3 className="onboarding-title">{step.title}</h3>
        <p className="onboarding-desc">{step.description}</p>

        {/* Step dots */}
        <div className="onboarding-dots">
          {TOUR_STEPS.map((_, i) => (
            <span key={i} className={`onboarding-dot${i === currentStep ? " active" : ""}`} />
          ))}
        </div>

        <div className="onboarding-actions">
          <button className="onboarding-skip" onClick={dismiss}>Skip tour</button>
          <div className="onboarding-nav">
            {currentStep > 0 && (
              <button className="onboarding-btn secondary" onClick={prev}>Back</button>
            )}
            <button className="onboarding-btn primary" onClick={next}>
              {isLast ? "Got it!" : "Next"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
