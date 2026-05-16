import { Component, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
  fallbackMessage?: string;
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

  componentDidCatch(error: Error, info: { componentStack: string }) {
    console.error("[DeepClean] Uncaught error:", error, info.componentStack);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-[50vh] p-8 text-center">
          <div className="flex items-center justify-center w-12 h-12 rounded-full bg-red-500/15 border border-red-500/25 mb-4">
            <AlertTriangle className="w-6 h-6 text-red-400" />
          </div>
          <h2 className="text-lg font-bold text-foreground mb-2">Something went wrong</h2>
          <p className="text-sm text-muted-foreground mb-1 max-w-md">
            {this.props.fallbackMessage ?? "An unexpected error occurred in this component."}
          </p>
          {this.state.error && (
            <pre className="mt-3 mb-5 text-[11px] font-mono text-red-400 bg-red-500/5 border border-red-500/15 rounded px-3 py-2 max-w-lg overflow-auto text-left">
              {this.state.error.message}
            </pre>
          )}
          <Button
            size="sm"
            variant="outline"
            className="gap-2"
            onClick={this.handleReset}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Try again
          </Button>
        </div>
      );
    }

    return this.props.children;
  }
}
