import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props  { children: ReactNode }
interface State  { hasError: boolean; error?: Error }

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('ErrorBoundary caught:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-dark-900 flex items-center justify-center p-8">
          <div className="card max-w-lg w-full text-center">
            <div className="text-5xl mb-4">💥</div>
            <h1 className="text-2xl font-bold text-red-400 mb-3">
              Something went wrong
            </h1>
            <p className="text-gray-400 mb-6 text-sm font-mono break-all">
              {this.state.error?.message ?? 'Unknown error'}
            </p>
            <button
              onClick={() => window.location.reload()}
              className="btn-primary"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
