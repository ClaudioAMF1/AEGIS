import { IntelligenceView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Inteligência" };

export default function IntelligencePage() {
  return <IntelligenceView />;
}
