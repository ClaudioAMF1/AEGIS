import { DashboardView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Central" };

export default function DashboardPage() {
  return <DashboardView />;
}
