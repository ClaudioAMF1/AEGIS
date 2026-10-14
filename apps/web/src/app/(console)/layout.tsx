import type { ReactNode } from "react";

import { ConsoleShell } from "@/components/shell/shell";

// The console renders only after the session is verified (client-side, against the API), so
// navigations into it are allowed to wait instead of being validated as instant.
export const instant = false;

export default function ConsoleLayout({ children }: { children: ReactNode }) {
  return <ConsoleShell>{children}</ConsoleShell>;
}
