"use client";

import { useQuery } from "@tanstack/react-query";

import { Empty, QueryState } from "@/components/ui/states";
import { api } from "@/lib/api";
import { useScope } from "@/lib/queries";
import type { Graph } from "@/lib/types";

import { EntityGraph } from "./entity-graph";

export function MiniGraph({ hours }: { hours: number }) {
  const scope = useScope();
  const end = new Date();
  const start = new Date(end.getTime() - hours * 3600_000);
  const query = useQuery({
    queryKey: ["graph", scope, "mini", hours],
    queryFn: () =>
      api.get<Graph>("/graph", {
        scope,
        only_flagged: true,
        start: start.toISOString(),
        limit: 600,
      }),
  });
  return (
    <QueryState
      query={query}
      isEmpty={(g) => g.nodes.length === 0}
      empty={<Empty title="Nenhuma entidade com alertas no período." />}
    >
      {(graph) => <EntityGraph graph={graph} height={300} interactive={false} />}
    </QueryState>
  );
}
