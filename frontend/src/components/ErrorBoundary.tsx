import { Component, type ReactNode } from "react";

/** Keeps a failing page from blanking the whole app: shows the error and lets the user retry or navigate away. */
export class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: string }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidUpdate(prev: { resetKey?: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="error-box" role="alert" style={{ flexDirection: "column", alignItems: "flex-start", gap: 8 }}>
        <strong>This page failed to render.</strong>
        <span className="small mono wrap-anywhere">{this.state.error.message}</span>
        <button className="btn btn-sm" onClick={() => this.setState({ error: null })}>Try again</button>
      </div>
    );
  }
}
