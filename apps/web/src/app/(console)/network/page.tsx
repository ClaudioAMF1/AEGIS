import { NetworkView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Rede" };

export default function NetworkPage() {
  return <NetworkView />;
}
