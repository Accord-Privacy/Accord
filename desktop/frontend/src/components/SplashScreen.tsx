import React, { useState, useEffect } from "react";

interface SplashScreenProps {
  ready: boolean;
}

/**
 * Full-screen loading splash shown while the app initializes.
 * Fades out smoothly once `ready` becomes true, then unmounts.
 */
export const SplashScreen: React.FC<SplashScreenProps> = ({ ready }) => {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    if (ready) {
      // Keep showing for a brief moment so the fade-out is visible
      const timer = setTimeout(() => setVisible(false), 500);
      return () => clearTimeout(timer);
    }
  }, [ready]);

  if (!visible) return null;

  return (
    <div className={`splash-screen${ready ? " splash-fade-out" : ""}`}>
      <div className="splash-logo">
        <span className="splash-accent">A</span>ccord
      </div>
      <div className="splash-loader">
        <span className="splash-dot" />
        <span className="splash-dot" />
        <span className="splash-dot" />
      </div>
      <div className="splash-status">Initializing&hellip;</div>
    </div>
  );
};
