import { SettingsView } from "./view";

// Rendered only after the console verifies the session (see the layout).
export const instant = false;

export const metadata = { title: "Configuração" };

export default function SettingsPage() {
  return <SettingsView />;
}
