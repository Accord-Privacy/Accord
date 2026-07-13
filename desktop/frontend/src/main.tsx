import React from "react";
import ReactDOM from "react-dom/client";
import DOMPurify from "dompurify";
import App from "./App";
import ErrorBoundary from "./ErrorBoundary";
import { TitleBar } from "./components/TitleBar";
import { migrateToKeyring } from "./identityStorage";
import "./styles.css";

// Make DOMPurify available globally for sanitization
(window as any).DOMPurify = DOMPurify;

// Migrate localStorage identities to OS keyring on first Tauri launch
migrateToKeyring().catch((e) => console.warn("Keyring migration failed:", e));

// Dev-only automation bridge (see src/dev/automationBridge.ts). Both branch
// conditions are build-time constants, so Vite eliminates this import (and the
// module) from production builds; scripts/release.sh asserts it stays out.
if (import.meta.env.DEV || import.meta.env.VITE_ACCORD_AUTOMATION === "1") {
  import("./dev/automationBridge");
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <div className="app-shell">
      <TitleBar />
      <div className="app-viewport">
        <ErrorBoundary>
          <App />
        </ErrorBoundary>
      </div>
    </div>
  </React.StrictMode>
);
