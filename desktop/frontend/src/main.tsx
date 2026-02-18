import React from "react";
import ReactDOM from "react-dom/client";
import DOMPurify from "dompurify";
import App from "./App";
import ErrorBoundary from "./ErrorBoundary";
import { migrateToKeyring } from "./identityStorage";
import "./styles.css";

// Make DOMPurify available globally for sanitization
(window as any).DOMPurify = DOMPurify;

// Migrate localStorage identities to OS keyring on first Tauri launch
migrateToKeyring().catch((e) => console.warn("Keyring migration failed:", e));

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
