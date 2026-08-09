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
          aria-label="Historical host attack view with animated source to target packet lanes"
        >
          <defs>
            <radialGradient :id="stageGlowGradientId" cx="50%" cy="42%" r="78%">
              <stop offset="0%" stop-color="rgba(54, 170, 255, 0.18)" />
              <stop offset="46%" stop-color="rgba(8, 24, 42, 0.94)" />
              <stop offset="100%" stop-color="rgba(2, 8, 16, 1)" />
            </radialGradient>
            <linearGradient :id="frameGradientId" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stop-color="rgba(94, 227, 255, 0.16)" />
              <stop offset="48%" stop-color="rgba(92, 245, 186, 0.56)" />
              <stop offset="100%" stop-color="rgba(255, 176, 96, 0.18)" />
            </linearGradient>
            <filter :id="arcGlowFilterId" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="3.2" result="blurred" />
              <feMerge>
                <feMergeNode in="blurred" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <filter :id="nodeGlowFilterId" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="4.4" result="nodeBlur" />
              <feMerge>
                <feMergeNode in="nodeBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <marker
              :id="attackMarkerId"
              viewBox="0 0 10 10"
              refX="8.2"
              refY="5"
              markerWidth="5.2"
              markerHeight="5.2"
              orient="auto"
            >
              <path d="M0,0 L10,5 L0,10 z" fill="rgba(255, 184, 116, 0.92)" />
            </marker>
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
            stroke="rgba(83, 166, 214, 0.18)"
            stroke-width="1"
            rx="24"
          />
          <rect
            :x="stagePadding + 8"
            :y="stagePadding + 8"
            :width="stageWidth - (stagePadding * 2) - 16"
            :height="stageHeight - (stagePadding * 2) - 16"
            fill="none"
            :stroke="`url(#${frameGradientId})`"
            stroke-width="1"
            rx="20"
            opacity="0.78"
          />

          <g class="host-radar-mesh">
            <path
              v-for="meshPath in backdropPaths"
              :key="meshPath.id"
              :d="meshPath.d"
              fill="none"
              :stroke="meshPath.stroke"
              :stroke-width="meshPath.strokeWidth"
              :stroke-dasharray="meshPath.dash"
              :opacity="meshPath.opacity"
            />
          </g>

          <g v-if="arcPaths.length" class="host-radar-arcs">
            <path
              v-for="arc in arcPaths"
              :key="`glow-${arc.id}`"
              :d="arc.d"
              fill="none"
              :stroke="arc.glow"
              :stroke-width="arc.strokeWidth + 2.8"
              stroke-linecap="round"
              :opacity="arc.glowOpacity"
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
              :opacity="arc.strokeOpacity"
              :marker-end="arc.markerEnd"
            />
            <circle
              v-for="arc in activeArcPaths"
              :key="`impact-${arc.id}`"
              :cx="arc.target.x"
              :cy="arc.target.y"
              :fill="arc.traceColor"
              r="2"
              opacity="0"
            >
              <animate attributeName="r" values="2;10;2" :dur="arc.duration" :begin="arc.begin" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0;0.24;0" :dur="arc.duration" :begin="arc.begin" repeatCount="indefinite" />
            </circle>
            <circle
              v-for="arc in activeArcPaths"
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
              :class="{ 'host-radar-node--historical': !node.activeNow }"
              :transform="`translate(${node.x}, ${node.y})`"
              :opacity="node.nodeOpacity"
              @click="navigateToHost(node)"
            >
              <title>{{ nodeTooltip(node) }}</title>
              <circle
                :r="node.haloRadius"
                :fill="node.glow"
                :opacity="node.activeNow ? 0.24 : 0.12"
                :filter="`url(#${nodeGlowFilterId})`"
              />
              <circle
                :r="node.ringRadius"
                fill="none"
                :stroke="node.ring"
                stroke-width="1"
                :opacity="node.activeNow ? 0.78 : 0.38"
              />
              <g :transform="`scale(${node.iconScale})`">
                <rect
                  x="-16"
                  y="-12"
                  width="32"
                  height="20"
                  rx="3.5"
                  :fill="node.body"
                  stroke="rgba(235, 246, 255, 0.82)"
                  stroke-width="0.85"
                />
                <rect
                  x="-12"
                  y="-9"
                  width="24"
                  height="13"
                  rx="2"
                  :fill="node.screen"
                />
                <rect
                  x="-2.8"
                  y="7.4"
                  width="5.6"
                  height="4.2"
                  rx="1"
                  :fill="node.body"
                />
                <rect
                  x="-10"
                  y="11.2"
                  width="20"
                  height="3.4"
                  rx="1.7"
                  :fill="node.base"
                />
              </g>
              <circle
                cx="10"
                cy="-9"
                r="3.2"
                :fill="node.badge"
                stroke="rgba(3, 10, 18, 0.92)"
                stroke-width="1"
              />
              <text
                :y="node.labelY"
                text-anchor="middle"
                fill="rgba(237, 244, 255, 0.96)"
                font-size="9.8px"
                font-weight="700"
                :opacity="node.labelOpacity"
              >
                {{ compactIp(node.ip) }}
              </text>
              <text
                :y="node.metricY"
                text-anchor="middle"
                fill="rgba(170, 200, 226, 0.86)"
                font-size="8.6px"
                font-weight="600"
                :opacity="node.metricOpacity"
              >
                {{ node.metricLabel }}
              </text>
            </g>
          </g>

          <g v-else class="host-radar-empty">
            <text
              :x="stageCenterX"
              :y="stageCenterY - 10"
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
              Public hosts remain visible as history and live attack lanes animate from source to target.
            </text>
          </g>
        </svg>

        <div class="host-radar-overlay">
          <div class="host-radar-overlay__eyebrow">Host Graph View</div>
          <div class="host-radar-overlay__copy">
            Public hosts stay in a live node graph while packet attacks animate from source to destination and older PCs fade into historical lanes.
          </div>
        </div>

        <div class="host-radar-legend">
          <span class="legend-chip legend-chip--live">Live attack</span>
          <span class="legend-chip legend-chip--history">Historical host</span>
          <span class="legend-chip legend-chip--pc">PC node</span>
        </div>
      </div>

      <div class="host-radar-summary">
        <div class="summary-card">
          <div class="summary-card__label">Live hosts</div>
          <div class="summary-card__value">{{ activeHostCount }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-card__label">Historical hosts</div>
          <div class="summary-card__value">{{ historicalHostCount }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-card__label">Live lanes</div>
          <div class="summary-card__value">{{ activeArcPaths.length }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-card__label">Busiest node</div>
          <div class="summary-card__value summary-card__value--sm">{{ busiestHostLabel }}</div>
        </div>
      </div>

      <div v-if="hotLanes.length" class="host-radar-lanes">
        <div v-for="lane in hotLanes" :key="lane.id" class="lane-card">
          <div class="lane-card__route">{{ compactIp(lane.source) }} -> {{ compactIp(lane.target) }}</div>
          <div class="lane-card__meta">
            {{ lane.packets }} packets · {{ lane.protocolLabel || "unknown" }} · {{ lane.activeNow ? "live" : "historical" }}
          </div>
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
const MAX_VISIBLE_HOSTS = 24;
const MAX_VISIBLE_LINKS = 28;
const MAX_HISTORICAL_HOSTS = 42;
const MAX_HISTORICAL_LINKS = 64;
const HISTORY_RETENTION_MS = 1000 * 60 * 45;

function normalizeIp(value) {
  return String(value || "").trim();
}

function normalizeProto(value) {
  return String(value || "unknown").trim().toLowerCase() || "unknown";
}

function isPublicHost(ip, fallbackPrivate = false) {
  return classifyHost(ip, fallbackPrivate) === "public";
}

function parseIpv4Octets(value) {
  const match = String(value || "").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return null;
  const octets = match.slice(1).map((item) => Number(item));
  return octets.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)
    ? octets
    : null;
}

function classifyHost(ip, fallbackPrivate = false) {
  const raw = normalizeIp(ip).toLowerCase();
  if (!raw) return fallbackPrivate ? "private" : "public";
  if (raw === "localhost" || raw === "::1") return "local";
  if (raw === "::") return "reserved";
  if (raw.includes(":")) {
    if (raw.startsWith("fe80:")) return "local";
    if (raw.startsWith("fc") || raw.startsWith("fd")) return "private";
    if (raw.startsWith("ff")) return "multicast";
    if (raw.startsWith("2001:db8")) return "reserved";
    return "public";
  }

  const octets = parseIpv4Octets(raw);
  if (!octets) return fallbackPrivate ? "private" : "public";
  const [a, b, c, d] = octets;

  if (a === 127) return "local";
  if (a === 169 && b === 254) return "local";
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
  if (a === 100 && b >= 64 && b <= 127) return "private";
  if (a === 198 && (b === 18 || b === 19)) return "private";
  if (a >= 224 && a <= 239) return "multicast";
  if (a === 0 || a >= 240 || (a === 255 && b === 255 && c === 255 && d === 255)) return "reserved";
  if (a === 192 && b === 0 && c === 0) return "reserved";
  if (a === 192 && b === 0 && c === 2) return "reserved";
  if (a === 192 && b === 88 && c === 99) return "reserved";
  if (a === 198 && b === 51 && c === 100) return "reserved";
  if (a === 203 && b === 0 && c === 113) return "reserved";
  return "public";
}

function protoPalette(proto) {
  if (proto === "tcp") {
    return {
      stroke: "rgba(93, 204, 255, 0.82)",
      glow: "rgba(93, 204, 255, 0.36)",
      trace: "rgba(162, 230, 255, 0.98)",
    };
  }
  if (proto === "udp") {
    return {
      stroke: "rgba(94, 244, 186, 0.8)",
      glow: "rgba(94, 244, 186, 0.34)",
      trace: "rgba(179, 255, 224, 0.98)",
    };
  }
  if (proto === "icmp" || proto === "icmpv6") {
    return {
      stroke: "rgba(255, 187, 98, 0.84)",
      glow: "rgba(255, 187, 98, 0.34)",
      trace: "rgba(255, 228, 182, 0.98)",
    };
  }
  return {
    stroke: "rgba(164, 142, 255, 0.76)",
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
      default: "Animated source-to-target packet flow with historical workstation nodes.",
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
      historicalHosts: [],
      historicalLinks: [],
    };
  },
  computed: {
    stageCenterX() {
      return this.stageWidth / 2;
    },
    stageCenterY() {
      return this.stageHeight / 2 + 4;
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
    attackMarkerId() {
      return `host-stage-attack-${this.stageUid}`;
    },
    backdropPaths() {
      return [
        {
          id: "mesh-left",
          d: this.buildBackdropArc(96, 336, 534, 152, -1, 0.2),
          stroke: "rgba(86, 214, 255, 0.18)",
          strokeWidth: 1.1,
          dash: "",
          opacity: 0.82,
        },
        {
          id: "mesh-core",
          d: this.buildBackdropArc(172, 244, 810, 230, 1, 0.16),
          stroke: "rgba(96, 245, 189, 0.14)",
          strokeWidth: 0.96,
          dash: "9 14",
          opacity: 0.9,
        },
        {
          id: "mesh-right",
          d: this.buildBackdropArc(440, 146, 886, 332, 1, 0.18),
          stroke: "rgba(255, 186, 114, 0.16)",
          strokeWidth: 1.06,
          dash: "",
          opacity: 0.8,
        },
        {
          id: "mesh-history",
          d: this.buildBackdropArc(84, 410, 896, 406, -1, 0.08),
          stroke: "rgba(122, 188, 255, 0.12)",
          strokeWidth: 0.9,
          dash: "6 16",
          opacity: 0.82,
        },
      ];
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
            weight: (entry.packets * 8) + (Math.log10(entry.bytes + 10) * 22),
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
            outgoingPackets: 0,
            incomingPackets: 0,
            outgoingBytes: 0,
            incomingBytes: 0,
            protocols: new Set(),
          });
        }
        return hosts.get(ip);
      };

      const publicPoints = Array.isArray(this.snapshot && this.snapshot.public_points)
        ? this.snapshot.public_points
        : [];
      publicPoints.forEach((row) => seedHost(row, false));
      this.topHosts.forEach((row) => seedHost(row, false));

      this.aggregatedLinks.forEach((link) => {
        const sourceHost = seedHost({ ip: link.source }, false);
        const targetHost = seedHost({ ip: link.target }, false);
        if (sourceHost) {
          sourceHost.trafficPackets += link.packets;
          sourceHost.trafficBytes += link.bytes;
          sourceHost.linkCount += 1;
          sourceHost.outgoingPackets += link.packets;
          sourceHost.outgoingBytes += link.bytes;
          link.protocols.forEach((proto) => sourceHost.protocols.add(proto));
        }
        if (targetHost) {
          targetHost.trafficPackets += link.packets;
          targetHost.trafficBytes += link.bytes;
          targetHost.linkCount += 1;
          targetHost.incomingPackets += link.packets;
          targetHost.incomingBytes += link.bytes;
          link.protocols.forEach((proto) => targetHost.protocols.add(proto));
        }
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
          const emphasis = host.openPorts >= 12 || host.trafficPackets >= 18
            ? 2
            : host.openPorts >= 6 || host.trafficPackets >= 10
              ? 1
              : 0;
          const role = host.outgoingPackets >= (host.incomingPackets * 1.28) && host.outgoingPackets >= 2
            ? "source"
            : host.incomingPackets >= (host.outgoingPackets * 1.28) && host.incomingPackets >= 2
              ? "target"
              : "relay";
          const theme = scopeTheme(host.scope, emphasis);
          const score = (host.trafficPackets * 7) +
            (Math.min(48, host.openPorts) * 4) +
            (Math.log10(host.trafficBytes + 10) * 18);
          return {
            ...host,
            protocols,
            emphasis,
            role,
            score,
            metricLabel: host.openPorts > 0 ? `${host.openPorts} ports` : `${host.trafficPackets} pkts`,
            ...theme,
          };
        })
        .sort((left, right) => right.score - left.score || left.ip.localeCompare(right.ip));
    },
    visibleNodes() {
      const selected = [];
      const seen = new Set();
      const hostLookup = new Map(this.historicalHosts.map((host) => [host.ip, host]));
      const pushHost = (value) => {
        const host = typeof value === "string" ? hostLookup.get(value) : value;
        if (!host || seen.has(host.ip) || selected.length >= MAX_VISIBLE_HOSTS) return;
        selected.push(host);
        seen.add(host.ip);
      };

      this.historicalLinks.slice(0, MAX_VISIBLE_LINKS).forEach((link) => {
        pushHost(link.source);
        pushHost(link.target);
      });
      this.historicalHosts.forEach((host) => pushHost(host));
      return selected;
    },
    layoutNodes() {
      const nodes = this.visibleNodes.slice(0, MAX_VISIBLE_HOSTS);
      if (!nodes.length) return [];

      const activeNodes = nodes.filter((node) => node.activeNow);
      const historicalNodes = nodes.filter((node) => !node.activeNow);
      return [
        ...this.distributeActiveGraphNodes(activeNodes),
        ...this.distributeHistoricalNodes(historicalNodes),
      ].slice(0, MAX_VISIBLE_HOSTS);
    },
    visibleLinks() {
      const visibleIps = new Set(this.layoutNodes.map((node) => node.ip));
      const rawLinks = this.historicalLinks
        .filter((link) => visibleIps.has(link.source) && visibleIps.has(link.target))
        .slice(0, MAX_VISIBLE_LINKS);
      const pairCounts = new Map();
      return rawLinks.map((link) => {
        const pairKey = [link.source, link.target].sort().join("__");
        const pairCount = pairCounts.get(pairKey) || 0;
        pairCounts.set(pairKey, pairCount + 1);
        return {
          ...link,
          curveSign: pairCount % 2 === 1 ? -1 : 1,
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
          const strength = Math.max(1, Math.min(2.4, 1 + (Math.log2((link.packets || 0) + 1) * 0.28)));
          const laneOpacity = link.activeNow
            ? 0.92
            : Math.max(0.2, (Number(link.staleFactor) || 0.2) * 0.52);
          return {
            id: `${link.id}-${index}`,
            source,
            target,
            active: Boolean(link.activeNow),
            d: this.buildArcPath(source, target, link.curveSign, link.curveLevel),
            stroke: palette.stroke,
            glow: palette.glow,
            traceColor: palette.trace,
            strokeWidth: strength,
            strokeOpacity: laneOpacity,
            glowOpacity: link.activeNow ? 0.18 : Math.max(0.06, laneOpacity * 0.38),
            traceRadius: Math.max(2.4, Math.min(4.2, 2.1 + (Math.log2((link.packets || 0) + 1) * 0.34))),
            duration: `${(2.7 + ((index % 5) * 0.22)).toFixed(2)}s`,
            begin: `${(index % 7) * 0.15}s`,
            markerEnd: link.activeNow ? `url(#${this.attackMarkerId})` : "",
            style: {
              animationDuration: `${(2.5 + ((index % 4) * 0.24)).toFixed(2)}s`,
              animationDelay: `${(index % 6) * 0.11}s`,
            },
          };
        })
        .filter(Boolean);
    },
    activeArcPaths() {
      return this.arcPaths.filter((arc) => arc.active);
    },
    activeHostCount() {
      return this.historicalHosts.filter((host) => host.activeNow).length;
    },
    historicalHostCount() {
      return this.historicalHosts.filter((host) => !host.activeNow).length;
    },
    visibleProtocolCount() {
      return new Set(this.visibleLinks.flatMap((link) => link.protocols || [])).size;
    },
    busiestHostLabel() {
      const hot = this.historicalHosts[0];
      return hot ? this.compactIp(hot.ip) : "n/a";
    },
    hotLanes() {
      return this.visibleLinks.slice(0, 6);
    },
  },
  watch: {
    snapshot: {
      deep: true,
      immediate: true,
      handler() {
        this.syncHistoryFromCurrentData();
      },
    },
    topHosts: {
      deep: true,
      handler() {
        this.syncHistoryFromCurrentData();
      },
    },
  },
  methods: {
    compactIp(value) {
      const ip = normalizeIp(value);
      if (ip.length <= 18) return ip;
      return `${ip.slice(0, 9)}...${ip.slice(-6)}`;
    },
    distributeActiveGraphNodes(nodes) {
      const ordered = [...nodes].sort((left, right) => right.score - left.score || left.ip.localeCompare(right.ip));
      if (!ordered.length) return [];
      if (ordered.length === 1) {
        return [this.decorateGraphNode(ordered[0], this.stageCenterX, 214, 0.72)];
      }
      if (ordered.length === 2) {
        return [
          this.decorateGraphNode(ordered[0], this.stageCenterX - 172, 224, 0.68),
          this.decorateGraphNode(ordered[1], this.stageCenterX + 172, 246, 0.68),
        ];
      }

      const anchor = ordered[0];
      const remainder = ordered.slice(1);
      const leftNodes = remainder.filter((node) => node.role === "source");
      const rightNodes = remainder.filter((node) => node.role === "target");
      const centerNodes = remainder.filter((node) => node.role !== "source" && node.role !== "target");
      const balancedCenter = centerNodes.concat(
        leftNodes.length > rightNodes.length ? leftNodes.splice(Math.ceil(leftNodes.length / 2)) : [],
        rightNodes.length > leftNodes.length ? rightNodes.splice(Math.ceil(rightNodes.length / 2)) : []
      );

      return [
        this.decorateGraphNode(anchor, this.stageCenterX, 186, 0.74),
        ...this.placeNodesOnArc(leftNodes, {
          centerX: 244,
          centerY: 250,
          radiusX: 118,
          radiusY: 116,
          startAngle: -126,
          endAngle: 48,
          baseScale: 0.62,
        }),
        ...this.placeNodesOnArc(balancedCenter, {
          centerX: this.stageCenterX,
          centerY: 300,
          radiusX: 238,
          radiusY: 84,
          startAngle: -170,
          endAngle: -12,
          baseScale: 0.58,
        }),
        ...this.placeNodesOnArc(rightNodes, {
          centerX: 736,
          centerY: 248,
          radiusX: 118,
          radiusY: 114,
          startAngle: 132,
          endAngle: 304,
          baseScale: 0.62,
        }),
      ];
    },
    placeNodesOnArc(nodes, config = {}) {
      const ordered = [...nodes].sort((left, right) => right.score - left.score || left.ip.localeCompare(right.ip));
      if (!ordered.length) return [];
      const centerX = Number(config.centerX) || this.stageCenterX;
      const centerY = Number(config.centerY) || this.stageCenterY;
      const radiusX = Math.max(24, Number(config.radiusX) || 120);
      const radiusY = Math.max(18, Number(config.radiusY) || 80);
      const startAngle = (Number(config.startAngle) || -140) * (Math.PI / 180);
      const endAngle = (Number(config.endAngle) || -40) * (Math.PI / 180);
      const baseScale = Number(config.baseScale) || 0.58;
      return ordered.map((node, index) => {
        const progress = ordered.length === 1 ? 0.5 : index / (ordered.length - 1);
        const angle = startAngle + ((endAngle - startAngle) * progress);
        const sway = ((index % 2 === 0 ? 1 : -1) * Math.min(14, 7 + ordered.length));
        const x = centerX + (Math.cos(angle) * radiusX) + (Math.sin(angle) * sway * 0.14);
        const y = centerY + (Math.sin(angle) * radiusY) + ((index % 2 === 0 ? -1 : 1) * sway * 0.34);
        return this.decorateGraphNode(node, x, y, baseScale);
      });
    },
    decorateGraphNode(node, x, y, baseScale = 0.58) {
      const iconScale = Math.min(0.78, baseScale + (node.emphasis * 0.04) + (node.activeNow ? 0.02 : 0));
      return {
        ...node,
        x,
        y,
        iconScale,
        haloRadius: 10.4 + (node.emphasis * 2.5),
        ringRadius: 7.8 + (node.emphasis * 1.7),
        labelY: 17,
        metricY: 28,
        nodeOpacity: 1,
        labelOpacity: 0.98,
        metricOpacity: 0.82,
      };
    },
    distributeHistoricalNodes(nodes) {
      const ordered = [...nodes]
        .sort((left, right) => (right.lastSeenAt || 0) - (left.lastSeenAt || 0) || left.ip.localeCompare(right.ip))
        .slice(0, Math.max(0, MAX_VISIBLE_HOSTS));
      const firstRowCount = Math.min(12, ordered.length);
      const secondRowCount = Math.min(12, Math.max(0, ordered.length - firstRowCount));
      const rows = [
        ordered.slice(0, firstRowCount),
        ordered.slice(firstRowCount, firstRowCount + secondRowCount),
      ].filter((row) => row.length);

      const yPositions = [454, 502];
      return rows.flatMap((row, rowIndex) => row.map((node, index) => {
        const progress = row.length === 1 ? 0.5 : index / (row.length - 1);
        const x = 98 + (progress * (this.stageWidth - 196));
        const archLift = Math.sin(progress * Math.PI) * (rowIndex === 0 ? 20 : 12);
        const baseNode = this.decorateGraphNode(node, x, (yPositions[rowIndex] || 502) - archLift, 0.34);
        return {
          ...baseNode,
          iconScale: Math.min(0.42, baseNode.iconScale),
          haloRadius: 6.8,
          ringRadius: 5.2,
          labelY: 14,
          metricY: 24,
          nodeOpacity: Math.max(0.34, Number(node.staleFactor || 0.34)),
          labelOpacity: Math.max(0.52, Number(node.staleFactor || 0.34)),
          metricOpacity: Math.max(0.4, Number(node.staleFactor || 0.34) * 0.92),
        };
      }));
    },
    syncHistoryFromCurrentData() {
      const now = Date.now();
      const currentHosts = this.hostIndex;
      const currentLinks = this.aggregatedLinks;

      const hostMap = new Map(
        this.historicalHosts.map((host) => [
          host.ip,
          {
            ...host,
            protocols: Array.isArray(host.protocols) ? host.protocols.slice() : [],
            activeNow: false,
          },
        ])
      );

      currentHosts.forEach((host) => {
        const existing = hostMap.get(host.ip);
        hostMap.set(host.ip, {
          ...existing,
          ...host,
          firstSeenAt: existing && existing.firstSeenAt ? existing.firstSeenAt : now,
          lastSeenAt: now,
          activeNow: true,
        });
      });

      let hosts = Array.from(hostMap.values())
        .map((host) => {
          const historyAgeMs = Math.max(0, now - Number(host.lastSeenAt || now));
          const staleFactor = host.activeNow
            ? 1
            : Math.max(0.28, 1 - Math.min(0.72, historyAgeMs / HISTORY_RETENTION_MS));
          return {
            ...host,
            historyAgeMs,
            staleFactor,
            metricLabel: host.activeNow
              ? (host.openPorts > 0 ? `${host.openPorts} ports` : `${host.trafficPackets} pkts`)
              : `hist ${Math.max(1, Math.round(historyAgeMs / 60000))}m`,
          };
        })
        .filter((host) => host.activeNow || host.historyAgeMs <= HISTORY_RETENTION_MS)
        .sort((left, right) =>
          Number(right.activeNow) - Number(left.activeNow) ||
          right.score - left.score ||
          (right.lastSeenAt || 0) - (left.lastSeenAt || 0) ||
          left.ip.localeCompare(right.ip)
        )
        .slice(0, MAX_HISTORICAL_HOSTS);

      const hostWhitelist = new Set(hosts.map((host) => host.ip));
      const linkMap = new Map(
        this.historicalLinks.map((link) => [
          link.id,
          {
            ...link,
            protocols: Array.isArray(link.protocols) ? link.protocols.slice() : [],
            activeNow: false,
          },
        ])
      );

      currentLinks.forEach((link) => {
        const existing = linkMap.get(link.id);
        linkMap.set(link.id, {
          ...existing,
          ...link,
          firstSeenAt: existing && existing.firstSeenAt ? existing.firstSeenAt : now,
          lastSeenAt: now,
          activeNow: true,
        });
      });

      const links = Array.from(linkMap.values())
        .filter((link) => hostWhitelist.has(link.source) && hostWhitelist.has(link.target))
        .map((link) => {
          const historyAgeMs = Math.max(0, now - Number(link.lastSeenAt || now));
          const staleFactor = link.activeNow
            ? 1
            : Math.max(0.22, 1 - Math.min(0.78, historyAgeMs / HISTORY_RETENTION_MS));
          return {
            ...link,
            historyAgeMs,
            staleFactor,
          };
        })
        .filter((link) => link.activeNow || link.historyAgeMs <= HISTORY_RETENTION_MS)
        .sort((left, right) =>
          Number(right.activeNow) - Number(left.activeNow) ||
          right.weight - left.weight ||
          (right.lastSeenAt || 0) - (left.lastSeenAt || 0) ||
          left.id.localeCompare(right.id)
        )
        .slice(0, MAX_HISTORICAL_LINKS);

      hosts = hosts.filter((host) => {
        if (host.activeNow) return true;
        return links.some((link) => link.source === host.ip || link.target === host.ip) || host.historyAgeMs <= HISTORY_RETENTION_MS;
      });

      this.historicalHosts = hosts;
      this.historicalLinks = links;
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
      const bend = Math.min(84, 18 + (distance * 0.12) + ((curveLevel - 1) * 12));
      const cx = mx + (nx * bend * curveSign);
      const cy = my + (ny * bend * curveSign);
      return `M${sx.toFixed(2)},${sy.toFixed(2)} Q${cx.toFixed(2)},${cy.toFixed(2)} ${tx.toFixed(2)},${ty.toFixed(2)}`;
    },
    buildBackdropArc(sx, sy, tx, ty, curveSign = 1, curvature = 0.18) {
      const dx = tx - sx;
      const dy = ty - sy;
      const distance = Math.hypot(dx, dy) || 1;
      const mx = (sx + tx) / 2;
      const my = (sy + ty) / 2;
      const nx = -dy / distance;
      const ny = dx / distance;
      const bend = Math.min(146, 18 + (distance * Math.max(0.04, curvature)));
      const cx = mx + (nx * bend * curveSign);
      const cy = my + (ny * bend * curveSign);
      return `M${sx.toFixed(2)},${sy.toFixed(2)} Q${cx.toFixed(2)},${cy.toFixed(2)} ${tx.toFixed(2)},${ty.toFixed(2)}`;
    },
    nodeTooltip(node) {
      const protocols = Array.isArray(node.protocols) && node.protocols.length
        ? node.protocols.join(", ")
        : "no protocol sample";
      const history = node.activeNow ? "live" : "historical";
      return `${node.ip} | public host | ${history} | ${node.trafficPackets} packets | ${node.openPorts} open ports | ${protocols}`;
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
    radial-gradient(circle at 12% 16%, rgba(76, 190, 255, 0.16), transparent 34%),
    radial-gradient(circle at 88% 14%, rgba(255, 177, 96, 0.08), transparent 28%),
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
    linear-gradient(180deg, rgba(145, 222, 255, 0.04), rgba(145, 222, 255, 0) 24%),
    radial-gradient(circle at 50% 50%, rgba(52, 230, 255, 0.04), transparent 48%);
  opacity: 0.74;
}

.host-radar-stage::after {
  content: "";
  position: absolute;
  top: 126px;
  left: -18%;
  width: 42%;
  height: 94px;
  pointer-events: none;
  background: linear-gradient(
    90deg,
    rgba(112, 220, 255, 0),
    rgba(112, 220, 255, 0.06),
    rgba(255, 182, 101, 0.18),
    rgba(112, 220, 255, 0)
  );
  transform: skewX(-18deg);
  animation: host-threat-sweep 9s linear infinite;
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

.legend-chip--live {
  border-color: rgba(255, 187, 98, 0.9);
}

.legend-chip--history {
  border-color: rgba(164, 182, 205, 0.56);
}

.legend-chip--pc {
  border-color: rgba(93, 204, 255, 0.84);
}

.host-radar-flow {
  stroke-dasharray: 10 13;
  animation: host-radar-flow 2.8s linear infinite;
}

.host-radar-trace {
  opacity: 0.98;
}

.host-radar-node {
  cursor: pointer;
  transition: opacity 180ms ease;
}

.host-radar-node--historical {
  cursor: default;
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

@keyframes host-threat-sweep {
  from {
    transform: translateX(0%) skewX(-18deg);
  }
  to {
    transform: translateX(300%) skewX(-18deg);
  }
}

@keyframes host-radar-flow {
  from {
    stroke-dashoffset: 52;
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
