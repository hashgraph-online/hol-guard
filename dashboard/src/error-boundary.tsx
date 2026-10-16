import { Component, type ReactNode } from "react";

import { isChunkLoadError } from "./lazy-workspace";

export const CHUNK_LOAD_ERROR_HEADLINE = "This screen couldn't load";
export const CHUNK_LOAD_ERROR_BODY =
  "Guard lost its connection while opening this page. Reload once Guard is running on this device.";
export const GENERIC_ERROR_HEADLINE = "This screen ran into a problem";
export const GENERIC_ERROR_BODY = "Reload this page, or go back home and try again.";
export const DASHBOARD_RELOAD_LABEL = "Reload dashboard";
export const DASHBOARD_GO_HOME_LABEL = "Go home";
export const DASHBOARD_TRY_AGAIN_LABEL = "Try again";
export const AUTO_RETRY_DELAY_MS = 1500;
export const AUTO_RETRY_WINDOW_MS = 30_000;

/**
 * A render failure right after Guard restarts (for example after an update) is
 * often transient: the next render sees settled data. Retry a generic failure
 * once per window before showing the error screen. Chunk-load failures have
 * their own reload recovery and are never retried in place.
 */
export function shouldAutoRetry(error: Error | null, lastAutoRetryAt: number | null, now: number): boolean {
  if (dashboardErrorCopy(error).kind !== "generic") return false;
  return lastAutoRetryAt === null || now - lastAutoRetryAt >= AUTO_RETRY_WINDOW_MS;
}

export function dashboardErrorCopy(error: Error | null): {
  kind: "chunk" | "generic";
  headline: string;
  body: string;
} {
  if (error && isChunkLoadError(error)) {
    return {
      kind: "chunk",
      headline: CHUNK_LOAD_ERROR_HEADLINE,
      body: CHUNK_LOAD_ERROR_BODY,
    };
  }
  return {
    kind: "generic",
    headline: GENERIC_ERROR_HEADLINE,
    body: GENERIC_ERROR_BODY,
  };
}

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onReset?: () => void;
  reload?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
  retrying: boolean;
  retryDecided: boolean;
}

// Show the placeholder while the automatic retry is pending, or for the frame
// between catching an error and deciding whether to retry it. Once the decision
// is made, a declined retry keeps the error screen visible even after the
// retry window expires.
export function showsRetryPlaceholder(
  state: { error: Error | null; retrying: boolean; retryDecided: boolean },
  lastAutoRetryAt: number | null,
  now: number,
): boolean {
  if (state.retrying) return true;
  return !state.retryDecided && shouldAutoRetry(state.error, lastAutoRetryAt, now);
}

export class ErrorBoundary extends Component<Props, State> {
  private lastAutoRetryAt: number | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null, retrying: false, retryDecided: false };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error, retrying: false, retryDecided: false };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("ErrorBoundary caught:", error, errorInfo);
    const now = Date.now();
    if (!shouldAutoRetry(error, this.lastAutoRetryAt, now)) {
      this.setState({ retryDecided: true });
      return;
    }
    this.lastAutoRetryAt = now;
    this.setState({ retrying: true, retryDecided: true });
    this.clearRetryTimer();
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.setState({ hasError: false, error: null, retrying: false, retryDecided: false });
    }, AUTO_RETRY_DELAY_MS);
  }

  componentWillUnmount() {
    this.clearRetryTimer();
  }

  private clearRetryTimer() {
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }

  private handleReload = () => {
    if (this.props.reload) {
      this.props.reload();
      return;
    }
    window.location.reload();
  };

  private handleGoHome = () => {
    this.clearRetryTimer();
    this.setState({ hasError: false, error: null, retrying: false, retryDecided: false });
    this.props.onReset?.();
  };

  private handleTryAgain = () => {
    this.clearRetryTimer();
    this.setState({ hasError: false, error: null, retrying: false, retryDecided: false });
  };

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }
    // Hold a quiet placeholder while the one automatic retry is pending, so a
    // transient failure never flashes the error screen.
    if (showsRetryPlaceholder(this.state, this.lastAutoRetryAt, Date.now())) {
      return <div className="py-12" aria-busy="true" />;
    }
    if (this.props.fallback) {
      return this.props.fallback;
    }
    const copy = dashboardErrorCopy(this.state.error);
    const showTryAgain = copy.kind === "generic";
    const showGoHome = Boolean(this.props.onReset);
    return (
      <div
        className="guard-surface-in flex flex-col items-center justify-center py-12 text-center"
        role="alert"
      >
        <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-brand-attention/10">
          <svg
            className="h-7 w-7 text-brand-attention"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"
            />
          </svg>
        </div>
        <h3 className="text-lg font-semibold tracking-tight text-brand-dark">{copy.headline}</h3>
        <p className="mx-auto mt-2 max-w-md text-sm text-brand-dark/70">{copy.body}</p>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
          <button
            type="button"
            onClick={this.handleReload}
            className="inline-flex min-h-11 items-center rounded-lg bg-brand-blue px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"
          >
            {DASHBOARD_RELOAD_LABEL}
          </button>
          {showGoHome ? (
            <button
              type="button"
              onClick={this.handleGoHome}
              className="inline-flex min-h-11 items-center rounded-lg border border-brand-dark/15 bg-white px-4 text-sm font-semibold text-brand-dark transition-colors hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"
            >
              {DASHBOARD_GO_HOME_LABEL}
            </button>
          ) : null}
          {showTryAgain ? (
            <button
              type="button"
              onClick={this.handleTryAgain}
              className="inline-flex min-h-11 items-center rounded-lg border border-brand-dark/15 bg-white px-4 text-sm font-semibold text-brand-dark transition-colors hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"
            >
              {DASHBOARD_TRY_AGAIN_LABEL}
            </button>
          ) : null}
        </div>
      </div>
    );
  }
}
