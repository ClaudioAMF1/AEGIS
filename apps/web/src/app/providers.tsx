"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MotionConfig } from "motion/react";
import type { ReactNode } from "react";

import { ApiError } from "@/lib/api";
import { useUi } from "@/lib/store";

let browserQueryClient: QueryClient | undefined;

function makeClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        refetchOnWindowFocus: false,
        retry: (count, error) =>
          !(error instanceof ApiError && [401, 403, 404, 422].includes(error.status)) && count < 2,
      },
    },
  });
}

function getQueryClient(): QueryClient {
  if (typeof window === "undefined") return makeClient();
  browserQueryClient ??= makeClient();
  return browserQueryClient;
}

export function Providers({ children }: { children: ReactNode }) {
  const motion = useUi((s) => s.motion);
  return (
    <QueryClientProvider client={getQueryClient()}>
      <MotionConfig reducedMotion={motion ? "user" : "always"}>{children}</MotionConfig>
    </QueryClientProvider>
  );
}
