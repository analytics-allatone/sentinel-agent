import React from "react";
import { useLocation } from "react-router-dom";

import "./ErrorBoundary.css";

/**
 * Catches a render-time crash and shows a recoverable page instead of the blank
 * white screen React leaves behind when it unmounts the tree.
 *
 * This is the net under a failing API: a request that errors, times out, or
 * answers in an unexpected shape leaves a screen holding data it did not expect,
 * and the throw happens later — in render, far from the request. React has no
 * other way to survive that.
 *
 * What it does NOT catch (React's own limits, not an oversight):
 *   - errors thrown inside event handlers — those are caught where they happen
 *   - errors in async callbacks that never touch render
 *   - errors during server-side rendering
 * Those still need their own try/catch at the call site.
 */
class ErrorBoundaryInner extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, showDetail: false };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidUpdate(prevProps) {
    // Navigating away is itself a recovery: the next screen should render, not
    // inherit the last one's failure.
    if (this.state.error && prevProps.resetKey !== this.props.resetKey) {
      this.setState({ error: null, showDetail: false });
    }
  }

  componentDidCatch(error, info) {
    // Keep the component stack — it names the screen that threw, which the
    // error message on its own usually does not.
    console.error("[💥 CRASH]", error, info && info.componentStack);
  }

  render() {
    const { error, showDetail } = this.state;
    if (!error) return this.props.children;

    const message = (error && error.message) || String(error);

    return (
      <div className="crash" role="alert">
        <div className="crash__card">
          <div className="crash__mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10.3 3.6 1.8 18a2 2 0 0 0 1.7 3h16.9a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0z" />
              <path d="M12 9v4M12 17h.01" />
            </svg>
          </div>

          <h1 className="crash__title">Something went wrong on this page</h1>

          <p className="crash__lead">
            The page stopped rendering, usually because data it was given did not
            look the way it expected. Nothing you did is lost — the rest of the
            app is still running.
          </p>

          <div className="crash__actions">
            <button
              type="button"
              className="crash__btn crash__btn--primary"
              onClick={() => this.setState({ error: null, showDetail: false })}
            >
              Try again
            </button>
            <button
              type="button"
              className="crash__btn"
              onClick={() => window.location.reload()}
            >
              Reload page
            </button>
            <a className="crash__btn" href="/app/dashboard">
              Go to Dashboard
            </a>
          </div>

          <button
            type="button"
            className="crash__detail-toggle"
            onClick={() => this.setState((s) => ({ showDetail: !s.showDetail }))}
            aria-expanded={showDetail}
          >
            {showDetail ? "Hide technical detail" : "Show technical detail"}
          </button>

          {showDetail && <pre className="crash__detail">{message}</pre>}
        </div>
      </div>
    );
  }
}

/**
 * The boundary itself has to be a class — only class components can catch — so
 * the route is read out here and handed down as a plain prop.
 */
export default function ErrorBoundary({ children }) {
  const location = useLocation();
  return (
    <ErrorBoundaryInner resetKey={location.pathname}>{children}</ErrorBoundaryInner>
  );
}
