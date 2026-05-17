import { Switch, Route, Router as WouterRouter } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SuiClientProvider, WalletProvider } from "@mysten/dapp-kit";
import { getFullnodeUrl } from "@mysten/sui/client";
import "@mysten/dapp-kit/dist/index.css";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Layout from "@/components/Layout";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AuthProvider } from "@/components/AuthProvider";
import Dashboard from "@/pages/Dashboard";
import Threats from "@/pages/Threats";
import ThreatDetail from "@/pages/ThreatDetail";
import Analyze from "@/pages/Analyze";
import Wallets from "@/pages/Wallets";
import NotFound from "@/pages/not-found";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
});

// Contracts are deployed on testnet — wallet must connect to the same network
const networks = {
  testnet: { url: getFullnodeUrl("testnet") },
  devnet:  { url: getFullnodeUrl("devnet") },
};

function Router() {
  return (
    <Layout>
      <ErrorBoundary>
        <Switch>
          <Route path="/" component={Dashboard} />
          <Route path="/threats/:id" component={ThreatDetail} />
          <Route path="/threats" component={Threats} />
          <Route path="/analyze" component={Analyze} />
          <Route path="/wallets" component={Wallets} />
          <Route component={NotFound} />
        </Switch>
      </ErrorBoundary>
    </Layout>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      {/* SuiClientProvider must sit inside QueryClientProvider */}
      <SuiClientProvider networks={networks} defaultNetwork="testnet">
        {/* autoConnect re-connects the last wallet on page load */}
        <WalletProvider autoConnect>
          <AuthProvider>
            <TooltipProvider>
              <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
                <Router />
              </WouterRouter>
              <Toaster />
            </TooltipProvider>
          </AuthProvider>
        </WalletProvider>
      </SuiClientProvider>
    </QueryClientProvider>
  );
}

export default App;