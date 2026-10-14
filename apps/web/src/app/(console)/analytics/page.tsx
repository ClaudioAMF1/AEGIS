import { AnalyticsView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Métricas" };

export default function AnalyticsPage() {
  return <AnalyticsView />;
}
