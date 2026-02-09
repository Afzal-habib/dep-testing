"use client";

import { Provider } from "react-redux";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeVariantProvider } from "@/components/theme-variant-provider";
import { ProfessionalSessionProvider } from "@/components/providers/professional-session-provider";
import { NavigationProvider } from "@/components/providers/navigation-provider";
import { NavigationLoadingBar } from "@/components/shared/navigation-loading-bar";
import { ServerSessionProvider } from "@/components/providers/session-provider-server";
import { RealtimeProvider } from "@/components/providers/realtime-provider";
import { store } from "@/store";
import dynamic from "next/dynamic";
import { memo, useMemo } from "react";

// Lazy load non-essential components for fast initial load
const Toaster = dynamic(() => import("@/components/ui/toaster").then(mod => ({ default: mod.Toaster })), {
  ssr: false,
  loading: () => null,
});

// Create QueryClient outside component to prevent recreation on every render
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10 * 60 * 1000, // Increased stale time for better performance
      gcTime: 15 * 60 * 1000, // Increased garbage collection time
      retry: 1,
      refetchOnWindowFocus: false,
      refetchOnMount: false,
      refetchOnReconnect: false, // Reduce network overhead
      networkMode: 'offlineFirst', // Better offline handling
    },
    mutations: {
      retry: 1,
      networkMode: 'offlineFirst',
    },
  },
});

export default memo(function ClientProviders({ children }: { children: React.ReactNode }) {
  return (
    <ServerSessionProvider>
      <Provider store={store}>
        <QueryClientProvider client={queryClient}>
          <ThemeVariantProvider>
            <ProfessionalSessionProvider>
              <RealtimeProvider>
                <NavigationProvider>
                  <NavigationLoadingBar />
                  {children}
                  <Toaster />
                </NavigationProvider>
              </RealtimeProvider>
            </ProfessionalSessionProvider>
          </ThemeVariantProvider>
        </QueryClientProvider>
      </Provider>
    </ServerSessionProvider>
  );
});