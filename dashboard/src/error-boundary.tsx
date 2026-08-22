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
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("ErrorBoundary caught:", error, errorInfo);
  }

  private handleReload = () => {
    if (this.props.reload) {
      this.props.reload();
      return;
    }
    window.location.reload();
  };

  private handleGoHome = () => {
    this.setState({ hasError: false, error: null });
    this.props.onReset?.();
  };

  private handleTryAgain = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (!this.state.hasError) {
      return this.props.children;
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
