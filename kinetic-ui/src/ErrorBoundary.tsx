import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '2rem', textAlign: 'center', color: '#FF4D4D' }}>
          <h2>Oops, something went wrong.</h2>
          <p>{this.state.error?.message}</p>
          <button 
            className="btn btn-primary"
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{ marginTop: '1rem' }}
          >
            Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
