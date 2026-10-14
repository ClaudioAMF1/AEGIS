import { IncidentsView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Incidentes" };

export default function IncidentsPage() {
  return <IncidentsView />;
}
