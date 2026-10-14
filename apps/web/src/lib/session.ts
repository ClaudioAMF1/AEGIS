"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useCallback } from "react";

import { api, ApiError, setCsrfToken } from "./api";
import type { Me } from "./types";
import { can } from "./utils";

export function useMe() {
  return useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      const me = await api.get<Me>("/auth/me");
      setCsrfToken(me.csrf_token);
      return me;
    },
    retry: (count, error) => !(error instanceof ApiError && error.status === 401) && count < 2,
    staleTime: 60_000,
  });
}

export function usePermission(permission: string): boolean {
  const { data } = useMe();
  return can(data?.permissions, permission);
}

export function useLogout() {
  const client = useQueryClient();
  const router = useRouter();
  return useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      setCsrfToken(null);
      client.clear();
      router.replace("/login");
    }
  }, [client, router]);
}
