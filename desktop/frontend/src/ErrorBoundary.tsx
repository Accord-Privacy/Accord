import { Component, ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
  /** Optional fallback UI to render instead of the default error screen */
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * Top-level error boundary that catches render errors and prevents white-screening.
 * Shows a friendly error message with Try Again and Reload options.
 */
class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Uncaught error:", error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100vh",
          backgroundColor: "var(--bg-primary, #1a1a2e)",
          color: "var(--text-primary, #e0e0e0)",
          fontFamily: "system-ui, -apple-system, sans-serif",
          padding: "2rem",
          textAlign: "center",
        }}>
          <div style={{ fontSize: "3rem", marginBottom: "1rem" }}>😵</div>
          <h1 style={{ fontSize: "1.5rem", marginBottom: "0.5rem" }}>Something went wrong</h1>
          <p style={{
            color: "var(--text-secondary, #a0a0a0)",
            marginBottom: "1.5rem",
            maxWidth: "400px",
          }}>
            An unexpected error occurred. You can try again or reload the page.
          </p>
          {this.state.error && (
            <pre style={{
              backgroundColor: "var(--bg-secondary, #16213e)",
              padding: "0.75rem 1rem",
              borderRadius: "6px",
              fontSize: "0.8rem",
              maxWidth: "500px",
              overflow: "auto",
              marginBottom: "1.5rem",
              color: "var(--text-secondary, #a0a0a0)",
            }}>
              {this.state.error.message}
            </pre>
          )}
          <div style={{ display: "flex", gap: "0.75rem" }}>
            <button
              onClick={this.handleReset}
              style={{
                padding: "0.5rem 1.25rem",
                borderRadius: "6px",
                border: "1px solid var(--border-color, #333)",
                backgroundColor: "var(--bg-secondary, #16213e)",
                color: "var(--text-primary, #e0e0e0)",
                cursor: "pointer",
                fontSize: "0.9rem",
              }}
            >
              Try Again
            </button>
            <button
              onClick={this.handleReload}
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
              Reload
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
