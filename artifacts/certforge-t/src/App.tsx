import { type ReactNode, useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ErrorBoundary } from '@/components/error-boundary';
import { AppShell } from '@/components/app-shell';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import NotFound from '@/pages/not-found';
import Home from '@/pages/home';
import InspectPage from '@/pages/inspect';
import MatchPage from '@/pages/match';
import ConvertPage from '@/pages/convert';
import CreatePage from '@/pages/create';
import {
  Route,
  Switch,
  useLocation,
  Router as WouterRouter,
} from 'wouter';

const queryClient = new QueryClient();

function Router() {
  const [generatedCertificate, setGeneratedCertificate] = useState<File | null>(null);
  const [location, setLocation] = useLocation();

  return (
    // Keep a shared shell (sidebar, navbar) outside the boundary so it
    // survives a page crash.
    <RoutedErrorBoundary>
      <AppShell>
        <Switch>
          <Route path="/" component={Home} />
          <Route path="/create">
            <CreatePage onInspectGeneratedCertificate={(file) => {
              setGeneratedCertificate(file);
              setLocation('/inspect');
            }} />
          </Route>
          <Route path="/inspect">
            <InspectPage initialCertificate={generatedCertificate} />
          </Route>
          <Route path="/match" component={MatchPage} />
          <Route path="/convert" component={ConvertPage} />
          <Route component={NotFound} />
        </Switch>
      </AppShell>
    </RoutedErrorBoundary>
  );
}

function RoutedErrorBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
