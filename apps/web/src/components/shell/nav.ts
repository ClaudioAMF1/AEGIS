import {
  Activity,
  BarChart3,
  Bot,
  Crosshair,
  FileText,
  Globe2,
  LayoutDashboard,
  type LucideIcon,
  Monitor,
  Network,
  Settings,
  ShieldAlert,
  Siren,
} from "lucide-react";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  key: string; // keyboard shortcut after "g"
}

export const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: "operação",
    items: [
      { href: "/dashboard", label: "central", icon: LayoutDashboard, key: "d" },
      { href: "/alerts", label: "alertas", icon: Siren, key: "a" },
      { href: "/incidents", label: "incidentes", icon: ShieldAlert, key: "i" },
      { href: "/events", label: "eventos", icon: Activity, key: "e" },
      { href: "/endpoints", label: "endpoints", icon: Monitor, key: "p" },
      { href: "/network", label: "rede", icon: Network, key: "n" },
    ],
  },
  {
    group: "detecção",
    items: [
      { href: "/detections", label: "regras", icon: Crosshair, key: "r" },
      { href: "/intelligence", label: "inteligência", icon: Globe2, key: "t" },
    ],
  },
  {
    group: "análise",
    items: [
      { href: "/assistant", label: "assistente", icon: Bot, key: "c" },
      { href: "/analytics", label: "métricas", icon: BarChart3, key: "m" },
      { href: "/reports", label: "relatórios", icon: FileText, key: "o" },
    ],
  },
  {
    group: "sistema",
    items: [{ href: "/settings", label: "configuração", icon: Settings, key: "s" }],
  },
];
