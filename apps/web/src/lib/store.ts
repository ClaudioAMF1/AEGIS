"use client";

import { create } from "zustand";
import { persist } from "zustand/middleware";

import type { Scope } from "./types";

export type Theme = "noite" | "fosforo" | "papel";

interface UiState {
  // Data mode: Live telemetry or the synthetic Demo dataset. Never mixed implicitly.
  mode: Exclude<Scope, "all">;
  theme: Theme;
  motion: boolean;
  introSeen: boolean;
  graph3d: boolean;
  setMode: (mode: UiState["mode"]) => void;
  setTheme: (theme: Theme) => void;
  setMotion: (motion: boolean) => void;
  setIntroSeen: () => void;
  setGraph3d: (value: boolean) => void;
}

export const useUi = create<UiState>()(
  persist(
    (set) => ({
      mode: "demo",
      theme: "noite",
      motion: true,
      introSeen: false,
      graph3d: false,
      setMode: (mode) => set({ mode }),
      setTheme: (theme) => {
        document.documentElement.dataset.theme = theme;
        set({ theme });
      },
      setMotion: (motion) => {
        document.documentElement.dataset.motion = motion ? "on" : "off";
        set({ motion });
      },
      setIntroSeen: () => set({ introSeen: true }),
      setGraph3d: (graph3d) => set({ graph3d }),
    }),
    { name: "aegis-ui" },
  ),
);

/** Inline script (runs before paint) that applies persisted theme/motion to avoid a flash. */
export const THEME_BOOTSTRAP = `try{var s=JSON.parse(localStorage.getItem("aegis-ui")||"{}").state||{};var d=document.documentElement;d.dataset.theme=s.theme||"noite";d.dataset.motion=s.motion===false?"off":"on";}catch(e){}`;
