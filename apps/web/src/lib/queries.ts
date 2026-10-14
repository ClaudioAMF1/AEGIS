"use client";

import { useQuery } from "@tanstack/react-query";

import { api } from "./api";
import { useUi } from "./store";
import type { Dashboard, Histogram } from "./types";

export function useScope() {
  return useUi((s) => s.mode);
}

export function useDashboard(hours = 24) {
  const scope = useScope();
  return useQuery({
    queryKey: ["dashboard", scope, hours],
    queryFn: () => api.get<Dashboard>("/dashboard", { scope, hours }),
    refetchInterval: 15_000,
  });
}

export function useHistogram(hours = 24, buckets = 48) {
  const scope = useScope();
  return useQuery({
    queryKey: ["histogram", scope, hours, buckets],
    queryFn: () => api.get<Histogram>("/events-histogram", { scope, hours, buckets }),
    refetchInterval: 30_000,
  });
}
