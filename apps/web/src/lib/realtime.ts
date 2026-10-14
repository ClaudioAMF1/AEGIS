"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useEffectEvent, useState } from "react";

export type RealtimeState = "connecting" | "open" | "closed";

export interface RealtimeEvent {
  type: string;
  [key: string]: unknown;
}

function socketUrl(): string {
  const configured = process.env.NEXT_PUBLIC_AEGIS_WS_URL;
  if (configured) return configured;
  const { protocol, host } = window.location;
  return `${protocol === "https:" ? "wss" : "ws"}://${host}/api/v1/stream`;
}

/**
 * Connects to the realtime stream and invalidates cached queries when the backend reports new
 * events, alerts or simulation progress. Reconnects with capped exponential backoff.
 */
export function useRealtime(enabled: boolean, onEvent?: (event: RealtimeEvent) => void) {
  const client = useQueryClient();
  const [state, setState] = useState<RealtimeState>("connecting");
  const [lastEventAt, setLastEventAt] = useState<number | null>(null);
  const handler = useEffectEvent((event: RealtimeEvent) => onEvent?.(event));

  useEffect(() => {
    if (!enabled) return;
    let socket: WebSocket | null = null;
    let attempt = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let closed = false;
    let pending: ReturnType<typeof setTimeout> | undefined;
    const invalidate = (keys: string[]) => {
      // Coalesce bursts (demo replays) into one refetch wave.
      if (pending) return;
      pending = setTimeout(() => {
        pending = undefined;
        keys.forEach((key) => client.invalidateQueries({ queryKey: [key] }));
      }, 400);
    };

    const connect = () => {
      setState("connecting");
      socket = new WebSocket(socketUrl());
      socket.onopen = () => {
        attempt = 0;
        setState("open");
      };
      socket.onmessage = (message) => {
        let event: RealtimeEvent;
        try {
          event = JSON.parse(message.data as string) as RealtimeEvent;
        } catch {
          return;
        }
        if (event.type === "ping" || event.type === "hello") return;
        setLastEventAt(Date.now());
        handler(event);
        if (event.type === "events") invalidate(["dashboard", "events", "histogram", "endpoints"]);
        if (event.type === "alerts" || event.type === "simulation" || event.type === "resync")
          invalidate(["dashboard", "alerts", "incidents", "events", "histogram", "endpoints",
            "simulations", "graph", "analytics"]);
      };
      socket.onclose = (close) => {
        setState("closed");
        if (closed || close.code === 4401 || close.code === 4403) return;
        attempt += 1;
        timer = setTimeout(connect, Math.min(30_000, 1000 * 2 ** attempt));
      };
    };
    connect();
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      if (pending) clearTimeout(pending);
      socket?.close();
    };
  }, [enabled, client]);

  return { state, lastEventAt };
}
