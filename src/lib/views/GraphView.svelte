<script lang="ts">
  import { onMount } from "svelte";
  import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type Simulation } from "d3-force";
  import { select } from "d3-selection";
  import { zoom, zoomIdentity, type ZoomTransform } from "d3-zoom";
  import { api } from "../api";
  import { errorMessage, toast, ui } from "../stores.svelte";
  import { btn, card } from "../ui";
  import type { GraphEdge, GraphNode, Trust } from "../types";

  type N = GraphNode & { x?: number; y?: number; fx?: number | null; fy?: number | null };
  type L = { source: N; target: N; weight: GraphEdge["weight"] };

  let svg = $state<SVGSVGElement>();
  let width = $state(800);
  let height = $state(560);
  let layout = $state.raw<{ nodes: N[]; links: L[] }>({ nodes: [], links: [] });
  let transform = $state.raw<ZoomTransform>(zoomIdentity);
  let loading = $state(true);
  let sim: Simulation<N, undefined> | undefined;
  let zoomer: ReturnType<typeof zoom<SVGSVGElement, unknown>> | undefined;

  const fill: Record<Trust, string> = {
    ultimate: "#10b981",
    full: "#10b981",
    marginal: "#f59e0b",
    none: "#9ca3af",
    unknown: "#9ca3af",
  };
  const edgeColor = { full: "#10b981", marginal: "#f59e0b", none: "#9ca3af" };

  async function load() {
    loading = true;
    try {
      const g = await api.trustGraph();
      const nodes: N[] = g.nodes.map((n) => ({ ...n }));
      const byId = new Map(nodes.map((n) => [n.id, n]));
      const links: L[] = g.edges
        .filter((e) => byId.has(e.from) && byId.has(e.to))
        .map((e) => ({ source: byId.get(e.from)!, target: byId.get(e.to)!, weight: e.weight }));

      // First own key anchors the centre of the map.
      const centre = nodes.find((n) => n.is_own);
      if (centre) Object.assign(centre, { fx: 0, fy: 0 });

      sim?.stop();
      sim = forceSimulation<N>(nodes)
        .force("link", forceLink<N, L>(links).id((n) => n.id).distance(120).strength(0.6))
        .force("charge", forceManyBody().strength(-380))
        .force("collide", forceCollide(34))
        .force("x", forceX(0).strength(0.04))
        .force("y", forceY(0).strength(0.04))
        .on("tick", () => (layout = { nodes, links }));
      layout = { nodes, links };
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    zoomer = zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 4])
      .on("zoom", (e) => (transform = e.transform));
    select(svg!).call(zoomer);
    load();
    return () => sim?.stop();
  });

  const reset = () => select(svg!).call(zoomer!.transform, zoomIdentity);
  const radius = (n: N) => (n.is_own ? 18 : 13);
</script>

<div class="mb-4 flex items-center justify-between">
  <h2 class="text-lg font-semibold">Trust Graph</h2>
  <div class="flex gap-2">
    <button class={btn.outline} onclick={reset}>Reset view</button>
    <button class={btn.outline} disabled={loading} onclick={load}>Reload</button>
  </div>
</div>

<div class="{card} relative p-0" bind:clientWidth={width} bind:clientHeight={height} style="height: calc(100vh - 11rem); min-height: 360px">
  <svg
    bind:this={svg}
    class="h-full w-full cursor-grab touch-none active:cursor-grabbing"
    viewBox="{-width / 2} {-height / 2} {width} {height}"
    role="img"
    aria-label="Web of trust graph. Scroll to zoom, drag to pan, click a key to open it."
  >
    <defs>
      {#each Object.entries(edgeColor) as [w, c]}
        <marker id="arrow-{w}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M0,0 L10,5 L0,10 z" fill={c} />
        </marker>
      {/each}
    </defs>

    <g transform="translate({transform.x} {transform.y}) scale({transform.k})">
      {#each layout.links as l}
        {@const dx = (l.target.x ?? 0) - (l.source.x ?? 0)}
        {@const dy = (l.target.y ?? 0) - (l.source.y ?? 0)}
        {@const len = Math.hypot(dx, dy) || 1}
        <line
          x1={(l.source.x ?? 0) + (dx / len) * radius(l.source)}
          y1={(l.source.y ?? 0) + (dy / len) * radius(l.source)}
          x2={(l.target.x ?? 0) - (dx / len) * (radius(l.target) + 4)}
          y2={(l.target.y ?? 0) - (dy / len) * (radius(l.target) + 4)}
          stroke={edgeColor[l.weight]}
          stroke-width={l.weight === "none" ? 1 : 2}
          stroke-opacity={l.weight === "none" ? 0.6 : 0.9}
          marker-end="url(#arrow-{l.weight})"
        />
      {/each}

      {#each layout.nodes as n (n.id)}
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <g
          transform="translate({n.x ?? 0} {n.y ?? 0})"
          class="cursor-pointer"
          role="button"
          tabindex="0"
          aria-label="{n.label}, validity {n.validity}"
          onclick={() => (ui.selected = n.id)}
          onkeydown={(e) => (e.key === "Enter" || e.key === " ") && (ui.selected = n.id)}
        >
          <circle
            r={radius(n)}
            fill={fill[n.validity]}
            fill-opacity={n.revoked ? 0.25 : 1}
            stroke={ui.selected === n.id ? "var(--color-accent)" : n.is_own ? "currentColor" : "transparent"}
            stroke-width={ui.selected === n.id ? 4 : 2}
          />
          {#if n.revoked}<line x1={-radius(n)} y1={radius(n)} x2={radius(n)} y2={-radius(n)} stroke="#ef4444" stroke-width="2" />{/if}
          <text y={radius(n) + 14} text-anchor="middle" class="fill-current text-[11px]">{n.label}</text>
        </g>
      {/each}
    </g>
  </svg>

  {#if !loading && layout.nodes.length === 0}
    <div class="absolute inset-0 flex items-center justify-center text-sm text-zinc-500">No keys yet.</div>
  {/if}

  <ul class="absolute bottom-3 left-3 grid gap-1 rounded-lg bg-white/90 p-2 text-xs shadow dark:bg-zinc-900/90" aria-label="Legend">
    <li class="flex items-center gap-2"><span class="inline-block size-3 rounded-full" style="background:#10b981"></span>Fully valid</li>
    <li class="flex items-center gap-2"><span class="inline-block size-3 rounded-full" style="background:#f59e0b"></span>Marginally valid</li>
    <li class="flex items-center gap-2"><span class="inline-block size-3 rounded-full" style="background:#9ca3af"></span>Unknown / untrusted</li>
    <li class="flex items-center gap-2"><span class="inline-block size-3 rounded-full border-2 border-current"></span>Your key</li>
    <li class="text-zinc-500">Arrow: signer → certified key</li>
  </ul>
</div>
