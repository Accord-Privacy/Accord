import React from "react";
import ReactDOM from "react-dom/client";
import DOMPurify from "dompurify";
import App from "./App";
import "./styles.css";

// Make DOMPurify available globally for sanitization
(window as any).DOMPurify = DOMPurify;

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
