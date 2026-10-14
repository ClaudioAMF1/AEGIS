import { Suspense } from "react";

import { Loading } from "@/components/ui/states";

import { IncidentView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Investigação" };

export default function IncidentPage({ params }: PageProps<"/incidents/[id]">) {
  return (
    <Suspense fallback={<Loading />}>
      {params.then(({ id }) => <IncidentView id={id} />)}
    </Suspense>
  );
}
