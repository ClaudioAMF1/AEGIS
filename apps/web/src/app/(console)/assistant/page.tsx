import { Suspense } from "react";

import { Loading } from "@/components/ui/states";

import { AssistantView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Assistente" };

export default function AssistantPage() {
  return (
    <Suspense fallback={<Loading />}>
      <AssistantView />
    </Suspense>
  );
}
