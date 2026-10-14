import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import type { ReactNode } from "react";

import { THEME_BOOTSTRAP } from "@/lib/store";

import "./globals.css";
import { Providers } from "./providers";

// IBM Plex Mono (SIL OFL 1.1, see ./fonts/OFL.txt), self-hosted: no third-party font request
// at runtime and no network access needed at build time.
const plex = localFont({
  src: [
    { path: "./fonts/ibm-plex-mono-400.woff2", weight: "400", style: "normal" },
    { path: "./fonts/ibm-plex-mono-500.woff2", weight: "500", style: "normal" },
    { path: "./fonts/ibm-plex-mono-600.woff2", weight: "600", style: "normal" },
  ],
  variable: "--font-plex",
  display: "swap",
});

export const metadata: Metadata = {
  title: { default: "AEGIS — Autonomous Cyber Defense Platform", template: "%s · AEGIS" },
  description:
    "Plataforma de operações de segurança: telemetria Linux, detecção baseada em regras Sigma, correlação, investigação de incidentes e assistente de IA fundamentado em evidências.",
  icons: { icon: "/favicon.svg" },
};

export const viewport: Viewport = {
  themeColor: "#0b0c0b",
  colorScheme: "dark light",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="pt-BR" data-theme="noite" className={plex.variable} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOTSTRAP }} />
      </head>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
