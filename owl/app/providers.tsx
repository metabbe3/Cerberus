"use client";

import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { useState } from "react";
import { Toaster } from "@/components/ui/sonner";

// Middleware answers an expired/missing session on /api/* with 401
// {error:"Not signed in"}; every fetch helper surfaces that as the Error
// message, so one cache-level hook sends the browser back to /login.
function onAuthError(e: unknown) {
  if (e instanceof Error && e.message === "Not signed in") {
    window.location.href = `/login?next=${encodeURIComponent(location.pathname + location.search)}`;
  }
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        queryCache: new QueryCache({ onError: onAuthError }),
        mutationCache: new MutationCache({ onError: onAuthError }),
      }),
  );
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider
        attribute="class"
        defaultTheme="system"
        enableSystem
        disableTransitionOnChange
      >
        {children}
        <Toaster />
      </ThemeProvider>
    </QueryClientProvider>
  );
}
