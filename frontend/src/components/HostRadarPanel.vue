<template>
  <DataPanel
    :title="title"
    :subtitle="subtitle"
    :loading="loading"
    :error="error"
    :last-updated="lastUpdated"
    :show-refresh="showRefresh"
    :live-refresh="liveRefresh"
    :live-enabled="liveEnabled"
    :show-header="showHeader"
    :keep-content-on-loading="true"
    @refresh="$emit('refresh')"
    @update:liveEnabled="$emit('update:liveEnabled', $event)"
  >
    <div class="host-radar-shell">
      <div class="host-radar-stage">
        <svg
          :viewBox="`0 0 ${stageWidth} ${stageHeight}`"
          role="img"
          aria-label="Host transit radar with live packet flow animations"
        >
          <defs>
            <radialGradient :id="stageGlowGradientId" cx="50%" cy="44%" r="74%">
              <stop offset="0%" stop-color="rgba(48, 181, 255, 0.22)" />
              <stop offset="48%" stop-color="rgba(8, 26, 48, 0.94)" />
              <stop offset="100%" stop-color="rgba(2, 8, 16, 1)" />
            </radialGradient>
            <linearGradient :id="frameGradientId" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stop-color="rgba(94, 227, 255, 0.16)" />
              <stop offset="50%" stop-color="rgba(92, 245, 186, 0.6)" />
              <stop offset="100%" stop-color="rgba(255, 176, 96, 0.16)" />
            </linearGradient>
            <filter :id="arcGlowFilterId" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="3.2" result="blurred" />
              <feMerge>
                <feMergeNode in="blurred" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <filter :id="nodeGlowFilterId" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="4.6" result="nodeBlur" />
              <feMerge>
                <feMergeNode in="nodeBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          <rect
            x="0"
            y="0"
            :width="stageWidth"
            :height="stageHeight"
            fill="rgba(3, 9, 17, 0.98)"
          />
          <rect
            :x="stagePadding"
            :y="stagePadding"
            :width="stageWidth - (stagePadding * 2)"
            :height="stageHeight - (stagePadding * 2)"
            :fill="`url(#${stageGlowGradientId})`"
            stroke="rgba(83, 166, 214, 0.22)"
            stroke-width="1"
            rx="20"
          />
          <rect
            :x="stagePadding + 7"
            :y="stagePadding + 7"
            :width="stageWidth - (stagePadding * 2) - 14"
            :height="stageHeight - (stagePadding * 2) - 14"
            fill="none"
            :stroke="`url(#${frameGradientId})`"
            stroke-width="1"
            rx="17"
            opacity="0.78"
          />

          <g class="host-radar-grid">
            <circle
              v-for="ring in stageRings"
              :key="ring.id"
              :cx="stageCenterX"
              :cy="stageCenterY"
              :r="ring.radius"
              fill="none"
              stroke="rgba(104, 181, 231, 0.12)"
              stroke-width="0.9"
              stroke-dasharray="5 8"
            />
            <line
              v-for="beam in stageBeams"
              :key="beam.id"
              :x1="stageCenterX"
              :y1="stageCenterY"
              :x2="beam.x"
              :y2="beam.y"
              stroke="rgba(108, 190, 240, 0.1)"
              stroke-width="0.8"
            />
          </g>

          <g v-if="arcPaths.length" class="host-radar-arcs">
            <path
              v-for="arc in arcPaths"
              :key="`glow-${arc.id}`"
              :d="arc.d"
              fill="none"
              :stroke="arc.glow"
              :stroke-width="arc.strokeWidth + 2.6"
              stroke-linecap="round"
              opacity="0.18"
              :filter="`url(#${arcGlowFilterId})`"
            />
            <path
              v-for="arc in arcPaths"
              :key="arc.id"
              :d="arc.d"
              fill="none"
              :stroke="arc.stroke"
              :stroke-width="arc.strokeWidth"
              stroke-linecap="round"
              class="host-radar-flow"
              :style="arc.style"
            />
            <circle
              v-for="arc in arcPaths"
              :key="`trace-${arc.id}`"
              :r="arc.traceRadius"
              :fill="arc.traceColor"
              class="host-radar-trace"
              :filter="`url(#${nodeGlowFilterId})`"
            >
              <animateMotion :dur="arc.duration" :begin="arc.begin" repeatCount="indefinite" :path="arc.d" />
            </circle>
          </g>

          <g v-if="layoutNodes.length" class="host-radar-nodes">
            <g
              v-for="node in layoutNodes"
              :key="node.ip"
              class="host-radar-node"
              :transform="`translate(${node.x}, ${node.y})`"
              @click="navigateToHost(node)"
            >
              <title>{{ nodeTooltip(node) }}</title>
              <circle
                :r="node.haloRadius"
                :fill="node.glow"
                opacity="0.28"
                :filter="`url(#${nodeGlowFilterId})`"
              />
              <circle
                :r="node.ringRadius"
                fill="none"
                :stroke="node.ring"
                stroke-width="1.1"
                opacity="0.8"
              />
              <g :transform="`scale(${node.iconScale})`">
                <rect
                  x="-20"
                  y="-16"
                  width="40"
                  height="24"
                  rx="4"
                  :fill="node.body"
                  stroke="rgba(235, 246, 255, 0.82)"
                  stroke-width="0.9"
                />
                <rect
                  x="-15"
                  y="-12"
                  width="30"
                  height="16"
                  rx="2.4"
                  :fill="node.screen"
                />
                <rect
                  x="-3.4"
                  y="9"
                  width="6.8"
                  height="5.4"
                  rx="1.2"
                  :fill="node.body"
                />
                <rect
                  x="-13"
                  y="14"
                  width="26"
                  height="4.2"
                  rx="2.1"
                  :fill="node.base"
                />
                <circle
                  cx="0"
                  cy="16.2"
                  r="1.1"
                  fill="rgba(239, 248, 255, 0.9)"
                />
              </g>
              <circle
                :cx="node.iconScale > 1 ? 16 : 13"
                cy="-13"
                r="4"
                :fill="node.badge"
                stroke="rgba(3, 10, 18, 0.92)"
                stroke-width="1.2"
              />
              <text
                y="38"
                text-anchor="middle"
                fill="rgba(237, 244, 255, 0.96)"
                font-size="11.5px"
                font-weight="700"
              >
                {{ compactIp(node.ip) }}
              </text>
              <text
                y="53"
                text-anchor="middle"
                fill="rgba(170, 200, 226, 0.86)"
                font-size="10px"
                font-weight="600"
              >
                {{ node.metricLabel }}
              </text>
            </g>
          </g>

          <g v-else class="host-radar-empty">
            <text
              :x="stageCenterX"
              :y="stageCenterY - 8"
              text-anchor="middle"
              fill="rgba(230, 239, 252, 0.94)"
              font-size="18px"
              font-weight="700"
            >
              Waiting for public host conversations
            </text>
            <text
              :x="stageCenterX"
              :y="stageCenterY + 18"
              text-anchor="middle"
              fill="rgba(164, 193, 220, 0.82)"
              font-size="12px"
            >
              Only routable public IPs are rendered here once live packet lanes appear between them.
            </text>
          </g>
        </svg>

        <div class="host-radar-overlay">
          <div class="host-radar-overlay__eyebrow">Host Transit View</div>
          <div class="host-radar-overlay__copy">
            Packet traces move only across public host pairs, with every endpoint rendered as a workstation icon.
          </div>
        </div>

        <div class="host-radar-legend">
          <span class="legend-chip legend-chip--public">Public host</span>
          <span class="legend-chip legend-chip--flow">Packet lane</span>
        </div>
      </div>

      <div class="host-radar-summary">
        <div class="summary-card">
          <div class="summary-card__label">Visible public hosts</div>
          <div class="summary-card__value">{{ layoutNodes.length }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-card__label">Public lanes</div>
          <div class="summary-card__value">{{ arcPaths.length }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-card__label">Protocols</div>
          <div class="summary-card__value">{{ visibleProtocolCount }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-card__label">Busiest node</div>
          <div class="summary-card__value summary-card__value--sm">{{ busiestHostLabel }}</div>
        </div>
      </div>

      <div v-if="hotLanes.length" class="host-radar-lanes">
        <div v-for="lane in hotLanes" :key="lane.id" class="lane-card">
          <div class="lane-card__route">{{ compactIp(lane.source) }} -> {{ compactIp(lane.target) }}</div>
          <div class="lane-card__meta">{{ lane.packets }} packets · {{ lane.protocolLabel }}</div>
        </div>
      </div>
    </div>
  </DataPanel>
</template>

<script>
import DataPanel from "./ui/DataPanel.vue";

const STAGE_WIDTH = 980;
const STAGE_HEIGHT = 560;
const STAGE_PADDING = 20;
const MAX_VISIBLE_HOSTS = 16;
const MAX_VISIBLE_LINKS = 20;

function normalizeIp(value) {
  return String(value || "").trim();
}

function normalizeProto(value) {
  return String(value || "unknown").trim().toLowerCase() || "unknown";
}

function isPublicHost(ip, fallbackPrivate = false) {
  return classifyHost(ip, fallbackPrivate) === "public";
}

function classifyHost(ip, fallbackPrivate = false) {
  const raw = normalizeIp(ip).toLowerCase();
  if (!raw) return fallbackPrivate ? "private" : "public";
  if (raw === "localhost" || raw === "::1" || raw.startsWith("127.")) return "local";
  if (raw.startsWith("10.") || raw.startsWith("192.168.")) return "private";
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(raw)) return "private";
  if (raw.startsWith("169.254.")) return "local";
  if (raw.startsWith("fc") || raw.startsWith("fd")) return "private";
  if (raw.startsWith("fe80:")) return "local";
  return fallbackPrivate ? "private" : "public";
}

function protoPalette(proto) {
  if (proto === "tcp") {
    return {
      stroke: "rgba(93, 204, 255, 0.78)",
      glow: "rgba(93, 204, 255, 0.34)",
      trace: "rgba(162, 230, 255, 0.96)",
    };
  }
  if (proto === "udp") {
    return {
      stroke: "rgba(94, 244, 186, 0.76)",
      glow: "rgba(94, 244, 186, 0.34)",
      trace: "rgba(179, 255, 224, 0.96)",
    };
  }
  if (proto === "icmp") {
    return {
      stroke: "rgba(255, 187, 98, 0.8)",
      glow: "rgba(255, 187, 98, 0.34)",
      trace: "rgba(255, 228, 182, 0.98)",
    };
  }
  return {
    stroke: "rgba(164, 142, 255, 0.74)",
    glow: "rgba(164, 142, 255, 0.3)",
    trace: "rgba(219, 211, 255, 0.96)",
  };
}

function scopeTheme(scope, emphasis = 0) {
  if (scope === "public") {
    return {
      body: emphasis >= 2 ? "rgba(255, 92, 112, 0.92)" : "rgba(46, 138, 255, 0.92)",
      screen: emphasis >= 2 ? "rgba(255, 204, 210, 0.94)" : "rgba(165, 223, 255, 0.95)",
      ring: emphasis >= 2 ? "rgba(255, 151, 166, 0.88)" : "rgba(116, 214, 255, 0.84)",
      glow: emphasis >= 2 ? "rgba(255, 92, 112, 0.42)" : "rgba(46, 138, 255, 0.34)",
      badge: emphasis >= 2 ? "rgba(255, 211, 111, 0.95)" : "rgba(126, 244, 255, 0.94)",
      base: emphasis >= 2 ? "rgba(255, 134, 148, 0.88)" : "rgba(126, 214, 255, 0.88)",
    };
  }
  if (scope === "local") {
    return {
      body: "rgba(255, 183, 82, 0.94)",
      screen: "rgba(255, 234, 192, 0.95)",
      ring: "rgba(255, 209, 144, 0.86)",
      glow: "rgba(255, 183, 82, 0.38)",
      badge: "rgba(255, 109, 109, 0.94)",
      base: "rgba(255, 214, 150, 0.88)",
    };
  }
  return {
    body: emphasis >= 2 ? "rgba(243, 177, 75, 0.92)" : "rgba(56, 205, 153, 0.9)",
    screen: emphasis >= 2 ? "rgba(255, 232, 187, 0.95)" : "rgba(194, 255, 233, 0.95)",
    ring: emphasis >= 2 ? "rgba(255, 217, 155, 0.84)" : "rgba(135, 251, 210, 0.82)",
    glow: emphasis >= 2 ? "rgba(243, 177, 75, 0.36)" : "rgba(56, 205, 153, 0.34)",
    badge: emphasis >= 2 ? "rgba(255, 121, 121, 0.95)" : "rgba(105, 233, 199, 0.94)",
    base: emphasis >= 2 ? "rgba(255, 208, 133, 0.86)" : "rgba(143, 255, 217, 0.88)",
  };
}

export default {
  name: "HostRadarPanel",
  components: {
    DataPanel,
  },
  props: {
    snapshot: {
      type: Object,
      default: () => ({}),
    },
    topHosts: {
      type: Array,
      default: () => [],
    },
    title: {
      type: String,
      default: "Host Transit Radar",
    },
    subtitle: {
      type: String,
      default: "Animated host-to-host packet flow with workstation nodes.",
    },
    loading: {
      type: Boolean,
      default: false,
    },
    error: {
      type: String,
      default: "",
    },
    lastUpdated: {
      type: String,
      default: "",
    },
    showRefresh: {
      type: Boolean,
      default: false,
    },
    liveRefresh: {
      type: Boolean,
      default: false,
    },
    liveEnabled: {
      type: Boolean,
      default: false,
    },
    showHeader: {
      type: Boolean,
      default: true,
    },
  },
  emits: ["refresh", "update:liveEnabled"],
  data() {
    return {
      stageWidth: STAGE_WIDTH,
      stageHeight: STAGE_HEIGHT,
      stagePadding: STAGE_PADDING,
      stageUid: Math.random().toString(16).slice(2, 10),
    };
  },
  computed: {
    stageCenterX() {
      return this.stageWidth / 2;
    },
    stageCenterY() {
      return this.stageHeight / 2 + 10;
    },
    stageGlowGradientId() {
      return `host-stage-glow-${this.stageUid}`;
    },
    frameGradientId() {
      return `host-stage-frame-${this.stageUid}`;
    },
    arcGlowFilterId() {
      return `host-stage-arc-${this.stageUid}`;
    },
    nodeGlowFilterId() {
      return `host-stage-node-${this.stageUid}`;
    },
    stageRings() {
      return [
        { id: "ring-1", radius: 110 },
        { id: "ring-2", radius: 192 },
        { id: "ring-3", radius: 276 },
        { id: "ring-4", radius: 348 },
      ];
    },
    stageBeams() {
      return Array.from({ length: 10 }, (_unused, index) => {
        const angle = (-Math.PI / 2) + ((Math.PI * 2 * index) / 10);
        return {
          id: `beam-${index}`,
          x: this.stageCenterX + (Math.cos(angle) * 364),
          y: this.stageCenterY + (Math.sin(angle) * 228),
        };
      });
    },
    aggregatedLinks() {
      const raw = Array.isArray(this.snapshot && this.snapshot.links) ? this.snapshot.links : [];
      const byKey = new Map();
      raw.forEach((row) => {
        const source = normalizeIp(row && row.source);
        const target = normalizeIp(row && row.target);
        if (!source || !target) return;
        if (!isPublicHost(source) || !isPublicHost(target)) return;
        const proto = normalizeProto(row && row.proto);
        const bytes = Math.max(1, Number(row && row.value) || 1);
        const key = `${source}__${target}`;
        if (!byKey.has(key)) {
          byKey.set(key, {
            id: key,
            source,
            target,
            packets: 0,
            bytes: 0,
            protoCounts: {},
          });
        }
        const entry = byKey.get(key);
        entry.packets += 1;
        entry.bytes += bytes;
        entry.protoCounts[proto] = (entry.protoCounts[proto] || 0) + 1;
      });
      return Array.from(byKey.values())
        .map((entry) => {
          const protocols = Object.entries(entry.protoCounts)
            .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
            .map(([proto]) => proto);
          return {
            ...entry,
            protocols,
            dominantProto: protocols[0] || "unknown",
            protocolLabel: protocols.slice(0, 3).join(", "),
            weight: (entry.packets * 8) + Math.log10(entry.bytes + 10) * 22,
          };
        })
        .sort((left, right) => right.weight - left.weight || left.id.localeCompare(right.id));
    },
    hostIndex() {
      const hosts = new Map();
      const seedHost = (row, fallbackPrivate = false) => {
        const ip = normalizeIp(row && (row.ip || row.id || row.label));
        if (!ip) return null;
        if (!isPublicHost(ip, fallbackPrivate)) return null;
        if (!hosts.has(ip)) {
          hosts.set(ip, {
            ip,
            label: ip,
            scope: classifyHost(ip, Boolean((row && row.private) || fallbackPrivate)),
            openPorts: 0,
            trafficPackets: 0,
            trafficBytes: 0,
            linkCount: 0,
            protocols: new Set(),
          });
        }
        return hosts.get(ip);
      };

      const publicPoints = Array.isArray(this.snapshot && this.snapshot.public_points) ? this.snapshot.public_points : [];
      publicPoints.forEach((row) => seedHost(row, false));
      this.topHosts.forEach((row) => seedHost(row, false));

      this.aggregatedLinks.forEach((link) => {
        const sourceHost = seedHost({ ip: link.source }, false);
        const targetHost = seedHost({ ip: link.target }, false);
        [sourceHost, targetHost].forEach((host) => {
          if (!host) return;
          host.trafficPackets += link.packets;
          host.trafficBytes += link.bytes;
          host.linkCount += 1;
          link.protocols.forEach((proto) => host.protocols.add(proto));
        });
      });

      this.topHosts.forEach((row) => {
        const ip = normalizeIp(row && (row.ip || row.label));
        if (!ip || !hosts.has(ip)) return;
        hosts.get(ip).openPorts = Math.max(
          hosts.get(ip).openPorts,
          Number(row && (row.value || row.open_ports || row.open_port_count)) || 0
        );
      });

      return Array.from(hosts.values())
        .map((host) => {
          const protocols = Array.from(host.protocols).sort();
          const emphasis = host.openPorts >= 12 || host.trafficPackets >= 18 ? 2 : host.openPorts >= 6 || host.trafficPackets >= 10 ? 1 : 0;
          const theme = scopeTheme(host.scope, emphasis);
          const score = (host.trafficPackets * 7) + (Math.min(48, host.openPorts) * 4) + (Math.log10(host.trafficBytes + 10) * 18);
          return {
            ...host,
            protocols,
            emphasis,
            score,
            metricLabel: host.openPorts > 0 ? `${host.openPorts} ports` : `${host.trafficPackets} packets`,
            ...theme,
          };
        })
        .sort((left, right) => right.score - left.score || left.ip.localeCompare(right.ip));
    },
    visibleNodes() {
      const selected = [];
      const seen = new Set();
      const pushHost = (host) => {
        if (!host || seen.has(host.ip) || selected.length >= MAX_VISIBLE_HOSTS) return;
        selected.push(host);
        seen.add(host.ip);
      };

      this.aggregatedLinks.slice(0, MAX_VISIBLE_LINKS).forEach((link) => {
        pushHost(this.hostIndex.find((host) => host.ip === link.source));
        pushHost(this.hostIndex.find((host) => host.ip === link.target));
      });
      this.hostIndex.forEach((host) => pushHost(host));
      return selected;
    },
    layoutNodes() {
      const nodes = this.visibleNodes.slice(0, MAX_VISIBLE_HOSTS);
      if (!nodes.length) return [];

      const layout = [];
      const center = nodes[0];
      layout.push({
        ...center,
        x: this.stageCenterX,
        y: this.stageCenterY,
        iconScale: 1.18,
        haloRadius: 38,
        ringRadius: 27,
      });

      const rings = [
        { capacity: 5, radiusX: 214, radiusY: 126, angleOffset: -Math.PI / 2 },
        { capacity: 6, radiusX: 330, radiusY: 186, angleOffset: -Math.PI / 3.2 },
        { capacity: 8, radiusX: 418, radiusY: 232, angleOffset: -Math.PI / 2.3 },
      ];
      let cursor = 1;
      rings.forEach((ring, ringIndex) => {
        const slice = nodes.slice(cursor, cursor + ring.capacity);
        cursor += ring.capacity;
        if (!slice.length) return;
        slice.forEach((node, index) => {
          const angle = ring.angleOffset + ((Math.PI * 2 * index) / slice.length);
          layout.push({
            ...node,
            x: this.stageCenterX + (Math.cos(angle) * ring.radiusX),
            y: this.stageCenterY + (Math.sin(angle) * ring.radiusY),
            iconScale: ringIndex === 0 ? 1.02 : 0.92,
            haloRadius: ringIndex === 0 ? 32 : 28,
            ringRadius: ringIndex === 0 ? 23 : 20,
          });
        });
      });
      return layout;
    },
    visibleLinks() {
      const visibleIps = new Set(this.layoutNodes.map((node) => node.ip));
      const rawLinks = this.aggregatedLinks
        .filter((link) => visibleIps.has(link.source) && visibleIps.has(link.target))
        .slice(0, MAX_VISIBLE_LINKS);
      const pairCounts = new Map();
      return rawLinks.map((link) => {
        const pairKey = [link.source, link.target].sort().join("__");
        const pairCount = pairCounts.get(pairKey) || 0;
        pairCounts.set(pairKey, pairCount + 1);
        const isReverseBias = pairCount % 2 === 1;
        return {
          ...link,
          curveSign: isReverseBias ? -1 : 1,
          curveLevel: Math.floor(pairCount / 2) + 1,
        };
      });
    },
    arcPaths() {
      const nodeLookup = new Map(this.layoutNodes.map((node) => [node.ip, node]));
      return this.visibleLinks
        .map((link, index) => {
          const source = nodeLookup.get(link.source);
          const target = nodeLookup.get(link.target);
          if (!source || !target) return null;
          const palette = protoPalette(link.dominantProto);
          const strength = Math.max(1.05, Math.min(2.8, 1 + (Math.log2(link.packets + 1) * 0.32)));
          return {
            id: `${link.id}-${index}`,
            source,
            target,
            d: this.buildArcPath(source, target, link.curveSign, link.curveLevel),
            stroke: palette.stroke,
            glow: palette.glow,
            traceColor: palette.trace,
            strokeWidth: strength,
            traceRadius: Math.max(2.8, Math.min(4.6, 2.4 + (Math.log2(link.packets + 1) * 0.38))),
            duration: `${(2.8 + ((index % 5) * 0.28)).toFixed(2)}s`,
            begin: `${(index % 7) * 0.16}s`,
            style: {
              animationDuration: `${(2.5 + ((index % 4) * 0.24)).toFixed(2)}s`,
              animationDelay: `${(index % 6) * 0.13}s`,
            },
          };
        })
        .filter(Boolean);
    },
    visibleProtocolCount() {
      return new Set(this.visibleLinks.flatMap((link) => link.protocols)).size;
    },
    busiestHostLabel() {
      if (!this.layoutNodes.length) return "n/a";
      return this.compactIp(this.layoutNodes[0].ip);
    },
    hotLanes() {
      return this.visibleLinks.slice(0, 6);
    },
  },
  methods: {
    compactIp(value) {
      const ip = normalizeIp(value);
      if (ip.length <= 18) return ip;
      return `${ip.slice(0, 9)}...${ip.slice(-6)}`;
    },
    buildArcPath(source, target, curveSign = 1, curveLevel = 1) {
      const sx = Number(source.x) || 0;
      const sy = Number(source.y) || 0;
      const tx = Number(target.x) || 0;
      const ty = Number(target.y) || 0;
      const dx = tx - sx;
      const dy = ty - sy;
      const distance = Math.hypot(dx, dy) || 1;
      const mx = (sx + tx) / 2;
      const my = (sy + ty) / 2;
      const nx = -dy / distance;
      const ny = dx / distance;
      const bend = Math.min(96, 24 + (distance * 0.16) + ((curveLevel - 1) * 18));
      const cx = mx + (nx * bend * curveSign);
      const cy = my + (ny * bend * curveSign);
      return `M${sx.toFixed(2)},${sy.toFixed(2)} Q${cx.toFixed(2)},${cy.toFixed(2)} ${tx.toFixed(2)},${ty.toFixed(2)}`;
    },
    nodeTooltip(node) {
      const protocols = node.protocols.length ? node.protocols.join(", ") : "no protocol sample";
      return `${node.ip} | public host | ${node.trafficPackets} packets | ${node.openPorts} open ports | ${protocols}`;
    },
    navigateToHost(node) {
      if (!node || !node.ip || !this.$router) return;
      this.$router.push({ path: "/investigate", query: { ip: node.ip } });
    },
  },
};
</script>

<style scoped>
.host-radar-shell {
  display: grid;
  gap: 16px;
}

.host-radar-stage {
  position: relative;
  overflow: hidden;
  border-radius: 24px;
  border: 1px solid rgba(94, 176, 226, 0.22);
  background:
    radial-gradient(circle at 12% 16%, rgba(76, 190, 255, 0.2), transparent 34%),
    radial-gradient(circle at 88% 14%, rgba(255, 177, 96, 0.12), transparent 28%),
    linear-gradient(180deg, rgba(4, 12, 24, 0.99), rgba(3, 8, 16, 0.98));
  box-shadow:
    inset 0 0 0 1px rgba(255, 255, 255, 0.03),
    inset 0 26px 80px rgba(39, 110, 174, 0.08),
    0 24px 60px rgba(3, 8, 15, 0.42);
}

.host-radar-stage::before {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background:
    linear-gradient(180deg, rgba(145, 222, 255, 0.05), rgba(145, 222, 255, 0) 24%),
    linear-gradient(180deg, rgba(120, 223, 255, 0) 0%, rgba(120, 223, 255, 0.08) 50%, rgba(120, 223, 255, 0) 100%);
  opacity: 0.72;
}

.host-radar-stage::after {
  content: "";
  position: absolute;
  inset: -18% 0 auto;
  height: 44%;
  pointer-events: none;
  background: linear-gradient(
    180deg,
    rgba(112, 220, 255, 0),
    rgba(112, 220, 255, 0.11),
    rgba(112, 220, 255, 0)
  );
  transform: translateY(-100%);
  animation: host-radar-scan 9s linear infinite;
}

.host-radar-stage svg {
  display: block;
  width: 100%;
  height: clamp(360px, 48vw, 620px);
  aspect-ratio: 16 / 9;
}

.host-radar-overlay {
  position: absolute;
  top: 18px;
  left: 18px;
  max-width: min(420px, calc(100% - 36px));
  padding: 14px 16px;
  border-radius: 18px;
  border: 1px solid rgba(107, 194, 232, 0.16);
  background: linear-gradient(180deg, rgba(7, 16, 30, 0.84), rgba(5, 10, 18, 0.74));
  backdrop-filter: blur(12px);
  box-shadow: 0 14px 30px rgba(2, 8, 15, 0.34);
}

.host-radar-overlay__eyebrow {
  color: rgba(116, 232, 255, 0.92);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.host-radar-overlay__copy {
  margin-top: 8px;
  color: rgba(205, 223, 241, 0.86);
  font-size: 0.92rem;
  line-height: 1.55;
}

.host-radar-legend {
  position: absolute;
  right: 18px;
  bottom: 18px;
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  max-width: min(420px, calc(100% - 36px));
}

.legend-chip {
  padding: 6px 11px;
  border-radius: 999px;
  border: 1px solid transparent;
  background: rgba(6, 13, 25, 0.8);
  color: rgba(224, 237, 250, 0.94);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  backdrop-filter: blur(10px);
}

.legend-chip--public {
  border-color: rgba(93, 204, 255, 0.9);
}

.legend-chip--flow {
  border-color: rgba(164, 142, 255, 0.9);
}

.host-radar-flow {
  stroke-dasharray: 11 14;
  animation: host-radar-flow 3s linear infinite;
}

.host-radar-trace {
  opacity: 0.98;
}

.host-radar-node {
  cursor: pointer;
}

.host-radar-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.summary-card {
  padding: 14px 16px;
  border-radius: 18px;
  border: 1px solid rgba(100, 184, 229, 0.14);
  background:
    linear-gradient(180deg, rgba(10, 17, 31, 0.88), rgba(6, 11, 19, 0.78)),
    radial-gradient(circle at 0% 0%, rgba(70, 174, 255, 0.12), transparent 42%);
}

.summary-card__label {
  color: rgba(157, 189, 216, 0.82);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.summary-card__value {
  margin-top: 10px;
  color: rgba(239, 245, 255, 0.98);
  font-family: var(--font-heading);
  font-size: 1.32rem;
  font-weight: 680;
}

.summary-card__value--sm {
  font-size: 1rem;
}

.host-radar-lanes {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.lane-card {
  padding: 14px 16px;
  border-radius: 16px;
  border: 1px solid rgba(96, 182, 226, 0.14);
  background:
    radial-gradient(circle at 100% 0%, rgba(78, 188, 255, 0.1), transparent 40%),
    linear-gradient(180deg, rgba(8, 16, 28, 0.88), rgba(4, 9, 17, 0.82));
}

.lane-card__route {
  color: rgba(239, 245, 255, 0.96);
  font-size: 0.82rem;
  font-weight: 700;
  letter-spacing: 0.02em;
}

.lane-card__meta {
  margin-top: 6px;
  color: rgba(165, 196, 222, 0.84);
  font-size: 0.76rem;
  font-weight: 600;
}

@keyframes host-radar-scan {
  from {
    transform: translateY(-110%);
  }
  to {
    transform: translateY(240%);
  }
}

@keyframes host-radar-flow {
  from {
    stroke-dashoffset: 54;
  }
  to {
    stroke-dashoffset: 0;
  }
}

@media (max-width: 1180px) {
  .host-radar-summary,
  .host-radar-lanes {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 780px) {
  .host-radar-stage svg {
    height: clamp(340px, 78vw, 520px);
  }

  .host-radar-overlay,
  .host-radar-legend {
    left: 12px;
    right: 12px;
    max-width: none;
  }

  .host-radar-legend {
    left: auto;
    justify-content: flex-start;
  }

  .host-radar-summary,
  .host-radar-lanes {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
