import { ReportsView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Relatórios" };

export default function ReportsPage() {
  return <ReportsView />;
}
