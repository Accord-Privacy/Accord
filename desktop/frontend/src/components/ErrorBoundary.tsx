import { Component, ErrorInfo, ReactNode } from "react";

interface ChatErrorBoundaryProps {
  children: ReactNode;
}

interface ChatErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

/**
 * Error boundary specifically for the chat area.
 * If the chat crashes, the sidebar and other UI remain functional.
 */
export class ChatErrorBoundary extends Component<ChatErrorBoundaryProps, ChatErrorBoundaryState> {
  constructor(props: ChatErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ChatErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Chat area error:", error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          flex: 1,
          padding: "2rem",
          color: "var(--text-primary, #e0e0e0)",
          textAlign: "center",
        }}>
          <div style={{ fontSize: "2rem", marginBottom: "0.75rem" }}>💬</div>
          <h2 style={{ fontSize: "1.2rem", marginBottom: "0.5rem" }}>Chat encountered an error</h2>
          <p style={{
            color: "var(--text-secondary, #a0a0a0)",
            marginBottom: "1rem",
            fontSize: "0.85rem",
          }}>
            Something went wrong loading the chat. Your sidebar and other features still work.
          </p>
          <button
            onClick={this.handleReset}
            style={{
              padding: "0.5rem 1.25rem",
              borderRadius: "6px",
              border: "none",
              backgroundColor: "var(--accent-color, #5865f2)",
              color: "#fff",
              cursor: "pointer",
              fontSize: "0.9rem",
            }}
          >
            Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

interface ModalErrorBoundaryProps {
  children: ReactNode;
}

interface ModalErrorBoundaryState {
  hasError: boolean;
}

/**
 * Error boundary for modals/settings — a crash in a modal won't kill the main app.
 */
export class ModalErrorBoundary extends Component<ModalErrorBoundaryProps, ModalErrorBoundaryState> {
  constructor(props: ModalErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(): ModalErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Modal/settings error:", error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: "2rem",
          color: "var(--text-primary, #e0e0e0)",
          textAlign: "center",
        }}>
          <p style={{ marginBottom: "0.75rem" }}>Something went wrong in this panel.</p>
          <button
            onClick={this.handleReset}
            style={{
              padding: "0.4rem 1rem",
              borderRadius: "6px",
              border: "none",
              backgroundColor: "var(--accent-color, #5865f2)",
              color: "#fff",
              cursor: "pointer",
              fontSize: "0.85rem",
            }}
          >
            Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
