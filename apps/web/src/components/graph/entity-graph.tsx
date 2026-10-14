"use client";

import type { Core, ElementDefinition, EventObject, StylesheetJson } from "cytoscape";
import { useEffect, useEffectEvent, useMemo, useRef, useState } from "react";

import type { Graph, GraphNode, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

export const KIND_LABEL: Record<GraphNode["kind"], string> = {
  host: "host",
  process: "processo",
  user: "usuário",
  ip: "ip",
  file: "arquivo",
  alert: "alerta",
};

const SHAPES: Record<GraphNode["kind"], string> = {
  host: "round-rectangle",
  process: "ellipse",
  user: "diamond",
  ip: "hexagon",
  file: "rectangle",
  alert: "triangle",
};

function css(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}

const severityVar: Record<Severity, string> = {
  critical: "--sev-critical",
  high: "--sev-high",
  medium: "--sev-medium",
  low: "--sev-low",
  informational: "--sev-info",
};

function stylesheet(): StylesheetJson {
  const text = css("--text");
  const muted = css("--muted");
  const border = css("--border");
  const dim = css("--dim");
  const accent = css("--accent");
  const bg = css("--bg");
  const surface = css("--surface");
  const sheet: StylesheetJson = [
    {
      selector: "node",
      style: {
        "background-color": surface,
        "border-width": 1,
        "border-color": muted,
        label: "data(label)",
        color: muted,
        "font-family": "IBM Plex Mono, monospace",
        "font-size": 8,
        "text-valign": "bottom",
        "text-margin-y": 4,
        "text-max-width": "110px",
        "text-wrap": "ellipsis",
        width: "mapData(weight, 1, 40, 12, 30)",
        height: "mapData(weight, 1, 40, 12, 30)",
        "overlay-opacity": 0,
      },
    },
    ...Object.entries(SHAPES).map(([kind, shape]) => ({
      selector: `node[kind = "${kind}"]`,
      style: { shape: shape as "ellipse" },
    })),
    { selector: 'node[kind = "host"]', style: { "border-color": text, color: text, width: 26, height: 20 } },
    { selector: 'node[kind = "user"]', style: { "border-color": accent } },
    { selector: "node[?intel]", style: { "border-color": css("--sev-critical"), "border-width": 2 } },
    ...Object.entries(severityVar).map(([sev, variable]) => ({
      selector: `node[severity = "${sev}"]`,
      style: { "border-color": css(variable), "border-width": 2 },
    })),
    ...Object.entries(severityVar).map(([sev, variable]) => ({
      selector: `node[kind = "alert"][severity = "${sev}"]`,
      style: { "background-color": css(variable), color: css(variable) },
    })),
    {
      selector: ":parent",
      style: {
        "background-opacity": 0.04,
        "background-color": text,
        "border-style": "dashed",
        "border-color": dim,
        "text-valign": "top",
        "text-margin-y": -4,
        color: text,
        padding: "14px",
      },
    },
    {
      selector: "edge",
      style: {
        width: "mapData(count, 1, 50, 1, 3)",
        "line-color": border,
        "target-arrow-color": border,
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.6,
        "curve-style": "bezier",
        label: "",
        "font-size": 7,
        color: muted,
        "text-background-color": bg,
        "text-background-opacity": 1,
      },
    },
    { selector: 'edge[kind = "flags"]', style: { "line-style": "dashed", "line-color": css("--sev-high"), "target-arrow-color": css("--sev-high") } },
    { selector: ".faded", style: { opacity: 0.12 } },
    { selector: "node:selected", style: { "border-color": accent, "border-width": 3, color: text } },
    { selector: "edge.highlight", style: { "line-color": accent, "target-arrow-color": accent, label: "data(kind)" } },
  ];
  return sheet;
}

export interface EntityGraphProps {
  graph: Graph;
  height?: number | string;
  groupByHost?: boolean;
  hiddenKinds?: Set<GraphNode["kind"]>;
  onSelect?: (node: GraphNode | null) => void;
  interactive?: boolean;
  className?: string;
  layoutSeed?: number;
}

/** 2D entity graph (Cytoscape). Works without WebGL; used as the accessible default view. */
export function EntityGraph({
  graph,
  height = 520,
  groupByHost = false,
  hiddenKinds,
  onSelect,
  interactive = true,
  className,
}: EntityGraphProps) {
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const [ready, setReady] = useState(false);
  const select = useEffectEvent((node: GraphNode | null) => onSelect?.(node));

  const elements = useMemo<ElementDefinition[]>(() => {
    const visible = graph.nodes.filter((n) => !hiddenKinds?.has(n.kind));
    const ids = new Set(visible.map((n) => n.id));
    const nodes: ElementDefinition[] = visible.map((n) => ({
      data: {
        id: n.id,
        label: n.label,
        kind: n.kind,
        severity: n.severity ?? undefined,
        weight: n.weight,
        intel: n.data.intel ? true : undefined,
        parent:
          groupByHost && n.kind === "process" && typeof n.data.host === "string"
            ? graph.nodes.find((h) => h.kind === "host" && h.label === n.data.host)?.id
            : undefined,
      },
    }));
    const edges: ElementDefinition[] = graph.edges
      .filter((e) => ids.has(e.source) && ids.has(e.target))
      .filter((e) => !(groupByHost && e.kind === "runs"))
      .map((e) => ({ data: { id: e.id, source: e.source, target: e.target, kind: e.kind, count: e.count } }));
    return [...nodes, ...edges];
  }, [graph, groupByHost, hiddenKinds]);

  useEffect(() => {
    let disposed = false;
    let instance: Core | null = null;
    void import("cytoscape").then(({ default: cytoscape }) => {
      if (disposed || !container.current) return;
      const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches ||
        document.documentElement.dataset.motion === "off";
      instance = cytoscape({
        container: container.current,
        elements,
        style: stylesheet(),
        layout: {
          name: "cose",
          animate: !reduce && elements.length < 400,
          animationDuration: 600,
          nodeRepulsion: () => 9000,
          idealEdgeLength: () => 60,
          padding: 24,
          randomize: false,
        } as cytoscape.LayoutOptions,
        minZoom: 0.2,
        maxZoom: 3,
        userZoomingEnabled: interactive,
        userPanningEnabled: interactive,
        boxSelectionEnabled: false,
        autoungrabify: !interactive,
      });
      instance.on("tap", "node", (event: EventObject) => {
        const target = event.target;
        instance?.elements().addClass("faded");
        target.closedNeighborhood().removeClass("faded");
        target.connectedEdges().addClass("highlight");
        const original = graph.nodes.find((n) => n.id === target.id()) ?? null;
        select(original);
      });
      instance.on("tap", (event: EventObject) => {
        if (event.target === instance) {
          instance?.elements().removeClass("faded highlight");
          select(null);
        }
      });
      cy.current = instance;
      setReady(true);
    });
    return () => {
      disposed = true;
      instance?.destroy();
      cy.current = null;
    };
  }, [elements, graph.nodes, interactive]);

  // Re-apply colors when the theme changes.
  useEffect(() => {
    const observer = new MutationObserver(() => cy.current?.style(stylesheet()));
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => observer.disconnect();
  }, []);

  return (
    <div className={cn("relative", className)}>
      <div
        ref={container}
        style={{ height }}
        className="hairline-grid w-full bg-ground/40"
        role="img"
        aria-label={`Grafo com ${graph.nodes.length} entidades e ${graph.edges.length} relações`}
      />
      {interactive && ready ? (
        <div className="absolute top-2 right-2 flex flex-col border border-border bg-ground text-xs">
          <button className="px-2 py-0.5 hover:text-accent" aria-label="Aproximar" onClick={() => cy.current?.zoom(cy.current.zoom() * 1.25)}>+</button>
          <button className="border-t border-border px-2 py-0.5 hover:text-accent" aria-label="Afastar" onClick={() => cy.current?.zoom(cy.current.zoom() / 1.25)}>−</button>
          <button className="border-t border-border px-2 py-0.5 text-2xs hover:text-accent" aria-label="Enquadrar" onClick={() => cy.current?.fit(undefined, 24)}>⤢</button>
        </div>
      ) : null}
    </div>
  );
}

export function GraphLegend() {
  return (
    <ul className="m-0 flex list-none flex-wrap gap-x-4 gap-y-1 p-0 text-2xs text-muted">
      <li>▢ host</li>
      <li>○ processo</li>
      <li>◇ usuário</li>
      <li>⬡ ip</li>
      <li>▭ arquivo</li>
      <li>△ alerta</li>
      <li><span className="text-critical">━</span> borda: severidade / intel</li>
    </ul>
  );
}
