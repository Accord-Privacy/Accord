import React, { useEffect, useState } from "react";
import { ConnectionInfo } from "../ws";

interface ConnectionBannerProps {
  connectionInfo: ConnectionInfo;
  onRetry: () => void;
}

const FAIL_THRESHOLD = 3;

export const ConnectionBanner: React.FC<ConnectionBannerProps> = ({ connectionInfo, onRetry }) => {
  const [dismissed, setDismissed] = useState(false);

  // Reset dismissed state when status changes
  useEffect(() => {
    if (connectionInfo.status !== "connected") {
      setDismissed(false);
    }
  }, [connectionInfo.status]);

  if (connectionInfo.status === "connected") {
    // Animate out briefly then hide
    return (
      <div
        className="connection-banner connection-banner--hidden"
        aria-hidden="true"
      />
    );
  }

  if (dismissed) return null;

  const failed =
    connectionInfo.status === "reconnecting" &&
    connectionInfo.reconnectAttempt >= FAIL_THRESHOLD;

  if (connectionInfo.status === "disconnected" && connectionInfo.reconnectAttempt === 0) {
    return null; // initial state, not yet attempted
  }

  return (
    <div
      className={`connection-banner ${
        failed ? "connection-banner--failed" : "connection-banner--reconnecting"
      }`}
      role="alert"
      onClick={failed ? onRetry : undefined}
    >
      {failed ? (
        <>Connection lost. Click to retry.</>
      ) : (
        <>
          <span className="connection-spinner" />
          Reconnecting...
        </>
      )}
    </div>
  );
};
