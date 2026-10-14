import { Suspense } from "react";

import { Loading } from "@/components/ui/states";

import { AlertsView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Alertas" };

export default function AlertsPage() {
  return (
    <Suspense fallback={<Loading />}>
      <AlertsView />
    </Suspense>
  );
}
