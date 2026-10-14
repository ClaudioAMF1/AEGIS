"use client";

import { Canvas, type ThreeEvent, useFrame, useThree } from "@react-three/fiber";
import { useEffect, useMemo, useRef, useState } from "react";
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";

import type { Graph, GraphNode, Severity } from "@/lib/types";

const MAX_NODES = 450;

function cssColor(name: string): THREE.Color {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return new THREE.Color(value || "#888888");
}

const SEVERITY_VAR: Record<Severity, string> = {
  critical: "--sev-critical",
  high: "--sev-high",
  medium: "--sev-medium",
  low: "--sev-low",
  informational: "--sev-info",
};

/** Deterministic 3D force layout (repulsion + springs), sized for a few hundred nodes. */
function layout(nodes: GraphNode[], edges: Graph["edges"]): Map<string, THREE.Vector3> {
  const n = nodes.length;
  const index = new Map(nodes.map((node, i) => [node.id, i]));
  const pos = nodes.map((_, i) => {
    // Fibonacci sphere seed: stable across renders, no randomness.
    const y = 1 - (i / Math.max(1, n - 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const theta = Math.PI * (3 - Math.sqrt(5)) * i;
    return new THREE.Vector3(Math.cos(theta) * r, y, Math.sin(theta) * r).multiplyScalar(40);
  });
  const links = edges
    .map((e) => [index.get(e.source), index.get(e.target)] as const)
    .filter((l): l is readonly [number, number] => l[0] !== undefined && l[1] !== undefined);
  const delta = new THREE.Vector3();
  const force = pos.map(() => new THREE.Vector3());
  for (let iter = 0; iter < 160; iter++) {
    const cooling = 1 - iter / 160;
    force.forEach((f) => f.set(0, 0, 0));
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        delta.subVectors(pos[i], pos[j]);
        const d2 = Math.max(delta.lengthSq(), 0.01);
        delta.multiplyScalar(220 / d2);
        force[i].add(delta);
        force[j].sub(delta);
      }
    }
    for (const [a, b] of links) {
      delta.subVectors(pos[b], pos[a]);
      const d = delta.length();
      delta.multiplyScalar((d - 14) * 0.04);
      force[a].add(delta);
      force[b].sub(delta);
    }
    for (let i = 0; i < n; i++) {
      force[i].addScaledVector(pos[i], -0.01); // gravity
      const step = Math.min(force[i].length(), 6 * cooling + 0.2);
      if (step > 0) pos[i].addScaledVector(force[i].normalize(), step);
    }
  }
  return new Map(nodes.map((node, i) => [node.id, pos[i]]));
}

function Controls() {
  const { camera, gl } = useThree();
  const controls = useRef<OrbitControls | null>(null);
  useEffect(() => {
    const instance = new OrbitControls(camera, gl.domElement);
    instance.enableDamping = true;
    instance.autoRotate = document.documentElement.dataset.motion !== "off" &&
      !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    instance.autoRotateSpeed = 0.4;
    controls.current = instance;
    return () => instance.dispose();
  }, [camera, gl]);
  useFrame(() => controls.current?.update());
  return null;
}

function Scene({
  graph,
  hiddenKinds,
  onSelect,
  onHover,
}: {
  graph: Graph;
  hiddenKinds?: Set<GraphNode["kind"]>;
  onSelect?: (node: GraphNode | null) => void;
  onHover: (info: { node: GraphNode; x: number; y: number } | null) => void;
}) {
  const nodes = useMemo(
    () => graph.nodes.filter((n) => !hiddenKinds?.has(n.kind)).slice(0, MAX_NODES),
    [graph.nodes, hiddenKinds],
  );
  const positions = useMemo(() => layout(nodes, graph.edges), [nodes, graph.edges]);
  const palette = useMemo(
    () => ({
      text: cssColor("--text"),
      muted: cssColor("--muted"),
      accent: cssColor("--accent"),
      border: cssColor("--border"),
      critical: cssColor("--sev-critical"),
    }),
    [],
  );
  const edgeGeometry = useMemo(() => {
    const points: number[] = [];
    for (const e of graph.edges) {
      const a = positions.get(e.source);
      const b = positions.get(e.target);
      if (a && b) points.push(a.x, a.y, a.z, b.x, b.y, b.z);
    }
    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute("position", new THREE.Float32BufferAttribute(points, 3));
    return geometry;
  }, [graph.edges, positions]);

  const colorFor = (node: GraphNode): THREE.Color => {
    if (node.severity) return cssColor(SEVERITY_VAR[node.severity]);
    if (node.data.intel) return palette.critical;
    if (node.kind === "host") return palette.text;
    if (node.kind === "user") return palette.accent;
    return palette.muted;
  };

  return (
    <>
      <lineSegments geometry={edgeGeometry}>
        <lineBasicMaterial color={palette.border} transparent opacity={0.7} />
      </lineSegments>
      {nodes.map((node) => {
        const p = positions.get(node.id);
        if (!p) return null;
        const size = node.kind === "host" ? 2.4 : node.kind === "alert" ? 1.8 : 0.8 + Math.min(1.4, node.weight / 25);
        return (
          <mesh
            key={node.id}
            position={p}
            onClick={(e: ThreeEvent<MouseEvent>) => {
              e.stopPropagation();
              onSelect?.(node);
            }}
            onPointerOver={(e: ThreeEvent<PointerEvent>) => {
              e.stopPropagation();
              onHover({ node, x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY });
            }}
            onPointerOut={() => onHover(null)}
          >
            {node.kind === "host" ? <boxGeometry args={[size, size, size]} /> : node.kind === "alert" ? <tetrahedronGeometry args={[size]} /> : node.kind === "ip" ? <octahedronGeometry args={[size]} /> : <sphereGeometry args={[size, 12, 12]} />}
            <meshBasicMaterial color={colorFor(node)} wireframe={node.kind === "host" || node.kind === "ip"} />
          </mesh>
        );
      })}
    </>
  );
}

/** Optional WebGL view. The 2D graph and the table remain the accessible defaults. */
export function Graph3D({
  graph,
  hiddenKinds,
  onSelect,
}: {
  graph: Graph;
  hiddenKinds?: Set<GraphNode["kind"]>;
  onSelect?: (node: GraphNode | null) => void;
}) {
  const [hover, setHover] = useState<{ node: GraphNode; x: number; y: number } | null>(null);
  const background = useMemo(() => cssColor("--bg"), []);
  return (
    <div className="relative h-[620px]" aria-label="Visualização 3D do grafo (decorativa; use a lista para leitura acessível)">
      <Canvas camera={{ position: [0, 0, 110], fov: 50 }} onPointerMissed={() => onSelect?.(null)} dpr={[1, 2]}>
        <color attach="background" args={[background]} />
        <Scene graph={graph} hiddenKinds={hiddenKinds} onSelect={onSelect} onHover={setHover} />
        <Controls />
      </Canvas>
      {hover ? (
        <div className="pointer-events-none absolute border border-dim bg-ground px-2 py-0.5 text-2xs" style={{ left: hover.x + 12, top: hover.y + 12 }}>
          {hover.node.kind}: {hover.node.label}
        </div>
      ) : null}
      {graph.nodes.length > MAX_NODES ? (
        <p className="absolute bottom-2 left-3 m-0 text-2xs text-medium">exibindo {MAX_NODES} de {graph.nodes.length} nós — refine os filtros</p>
      ) : null}
    </div>
  );
}
