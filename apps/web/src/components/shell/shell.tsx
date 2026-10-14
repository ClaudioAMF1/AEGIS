"use client";

import { useQuery } from "@tanstack/react-query";
import { Menu, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { type ReactNode, useEffect, useState } from "react";

import { Wordmark } from "@/components/brand";
import { Loading } from "@/components/ui/states";
import { api, ApiError } from "@/lib/api";
import { useRealtime } from "@/lib/realtime";
import { useLogout, useMe } from "@/lib/session";
import { useUi } from "@/lib/store";
import type { Dashboard } from "@/lib/types";
import { cn } from "@/lib/utils";

import { NAV } from "./nav";
import { StatusBar } from "./status-bar";

function ModeSwitch() {
  const mode = useUi((s) => s.mode);
  const setMode = useUi((s) => s.setMode);
  return (
    <div role="radiogroup" aria-label="Fonte de dados" className="flex border border-border text-2xs">
      {(["live", "demo"] as const).map((value) => (
        <button
          key={value}
          role="radio"
          aria-checked={mode === value}
          onClick={() => setMode(value)}
          className={cn(
            "px-2 py-0.5 uppercase tracking-[0.8px]",
            mode === value
              ? value === "demo"
                ? "bg-demo text-ground"
                : "bg-accent text-ground"
              : "text-muted hover:text-text",
          )}
        >
          {value === "live" ? "live" : "demo"}
        </button>
      ))}
    </div>
  );
}

function NavLinks({ onNavigate, openAlerts }: { onNavigate?: () => void; openAlerts?: number }) {
  const pathname = usePathname();
  return (
    <nav aria-label="Navegação principal" className="flex flex-col gap-4">
      {NAV.map((group) => (
        <div key={group.group}>
          <p className="eyebrow mb-1 px-2">{group.group}</p>
          <ul className="m-0 list-none p-0">
            {group.items.map((item) => {
              const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
              const Icon = item.icon;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "group flex items-center gap-2 border-l px-2 py-[3px] text-sm",
                      active
                        ? "border-accent bg-raised text-text"
                        : "border-transparent text-muted hover:border-dim hover:text-text",
                    )}
                  >
                    <Icon className="size-3.5 shrink-0" strokeWidth={1.5} aria-hidden />
                    <span className="flex-1">{item.label}</span>
                    {item.href === "/alerts" && openAlerts ? (
                      <span className="text-2xs text-warm tabular">{openAlerts}</span>
                    ) : (
                      <span className="text-2xs text-dim opacity-0 group-hover:opacity-100">
                        g{item.key}
                      </span>
                    )}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function useShortcuts() {
  const router = useRouter();
  useEffect(() => {
    let armed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) return;
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      if (event.key === "g") {
        armed = true;
        clearTimeout(timer);
        timer = setTimeout(() => (armed = false), 1200);
        return;
      }
      if (!armed) return;
      armed = false;
      const item = NAV.flatMap((g) => g.items).find((i) => i.key === event.key);
      if (item) router.push(item.href);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [router]);
}

export function ConsoleShell({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const me = useMe();
  const logout = useLogout();
  const mode = useUi((s) => s.mode);
  const [drawer, setDrawer] = useState(false);
  const authenticated = Boolean(me.data);
  const realtime = useRealtime(authenticated);
  useShortcuts();

  const summary = useQuery({
    queryKey: ["dashboard", mode, "shell"],
    queryFn: () => api.get<Dashboard>("/dashboard", { scope: mode, hours: 24 }),
    enabled: authenticated,
    refetchInterval: 30_000,
  });

  useEffect(() => {
    if (me.error instanceof ApiError && me.error.status === 401) {
      router.replace(`/login?next=${encodeURIComponent(pathname)}`);
    }
  }, [me.error, pathname, router]);


  if (!me.data) {
    return (
      <div className="grid min-h-svh place-items-center">
        {me.error && !(me.error instanceof ApiError && me.error.status === 401) ? (
          <p className="text-xs text-critical">API indisponível: {(me.error as Error).message}</p>
        ) : (
          <Loading label="verificando sessão" />
        )}
      </div>
    );
  }

  const openAlerts = summary.data?.metrics.find((m) => m.key === "open_alerts")?.value ?? undefined;

  return (
    <div className="flex min-h-svh flex-col" data-mode={mode}>
      {mode === "demo" ? (
        <div
          role="status"
          className="border-b border-demo/40 bg-demo/10 px-4 py-0.5 text-center text-2xs tracking-[0.8px] text-demo uppercase"
        >
          ◆ modo demo — dados sintéticos de laboratório, isolados da telemetria real
        </div>
      ) : null}
      <div className="flex min-h-0 flex-1">
        <aside className="sticky top-0 hidden h-svh w-[208px] shrink-0 flex-col border-r border-border px-3 py-4 lg:flex">
          <Link href="/dashboard" className="mb-6 px-2">
            <Wordmark />
          </Link>
          <NavLinks openAlerts={openAlerts ?? undefined} />
          <div className="mt-auto px-2 text-2xs text-dim">
            <p className="m-0">g + tecla navega</p>
          </div>
        </aside>

        {drawer ? (
          <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true">
            <button
              aria-label="Fechar menu"
              className="absolute inset-0 bg-black/60"
              onClick={() => setDrawer(false)}
            />
            <div className="absolute inset-y-0 left-0 w-[240px] overflow-y-auto border-r border-border bg-ground px-3 py-4">
              <div className="mb-6 flex items-center justify-between px-2">
                <Wordmark />
                <button onClick={() => setDrawer(false)} aria-label="Fechar menu">
                  <X className="size-4" />
                </button>
              </div>
              <NavLinks onNavigate={() => setDrawer(false)} openAlerts={openAlerts ?? undefined} />
            </div>
          </div>
        ) : null}

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-30 flex h-11 items-center gap-3 border-b border-border bg-ground/90 px-4 backdrop-blur">
            <button
              className="lg:hidden"
              aria-label="Abrir menu"
              onClick={() => setDrawer(true)}
            >
              <Menu className="size-4" />
            </button>
            <span className="lg:hidden">
              <Wordmark />
            </span>
            <div className="ml-auto flex items-center gap-3">
              <ModeSwitch />
              <span className="hidden text-2xs text-muted sm:inline">
                {me.data.display_name}
                <span className="text-dim"> · {me.data.role}</span>
              </span>
              <button onClick={logout} className="text-2xs text-muted hover:text-text">
                sair
              </button>
            </div>
          </header>
          <main id="main" className="min-w-0 flex-1 px-4 py-5 lg:px-6">
            {children}
          </main>
          <StatusBar
            me={me.data}
            dashboard={summary.data}
            realtime={realtime.state}
            lastEventAt={realtime.lastEventAt}
          />
        </div>
      </div>
    </div>
  );
}
