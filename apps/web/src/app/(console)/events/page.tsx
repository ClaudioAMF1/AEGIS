import { Suspense } from "react";

import { Loading } from "@/components/ui/states";

import { EventsView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Eventos" };

export default function EventsPage() {
  return (
    <Suspense fallback={<Loading />}>
      <EventsView />
    </Suspense>
  );
}
