import { DetectionsView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Regras" };

export default function DetectionsPage() {
  return <DetectionsView />;
}
