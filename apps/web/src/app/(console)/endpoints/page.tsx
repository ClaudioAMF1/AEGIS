import { Suspense } from "react";

import { Loading } from "@/components/ui/states";

import { EndpointsView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Endpoints" };

export default function EndpointsPage() {
  return (
    <Suspense fallback={<Loading />}>
      <EndpointsView />
    </Suspense>
  );
}
