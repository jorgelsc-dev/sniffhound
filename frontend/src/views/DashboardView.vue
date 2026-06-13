<template>
  <div>
    <ViewHeader
      overline="Operations"
      title="Dashboard"
      description="Runtime control, live telemetry metrics, active sessions, and the latest traffic crossing SniffHound."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-row dense>
      <v-col v-for="metric in metricCards" :key="metric.key" cols="12" sm="6" xl="2">
        <v-card variant="tonal" class="pa-5 metric-card">
          <div class="d-flex align-center justify-space-between ga-3">
            <div>
              <div class="text-caption text-medium-emphasis">{{ metric.label }}</div>
              <div class="text-h5 font-weight-bold" :class="metric.colorClass">{{ metric.value }}</div>
            </div>
            <v-icon :icon="metric.icon" class="metric-icon" :class="metric.colorClass" />
          </div>
          <div class="text-caption text-medium-emphasis mt-3">{{ metric.caption }}</div>
        </v-card>
      </v-col>
    </v-row>

    <v-alert v-if="error" type="error" variant="tonal" class="my-6">
      {{ error }}
    </v-alert>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="7">
        <DataPanel
          title="Runtime Posture"
          subtitle="Both engines stay visible. Sniffer blockers and honeypot listener readiness are surfaced here."
          v-model:live-enabled="liveRefreshEnabled"
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :live-refresh="true"
          @refresh="load"
        >
          <div class="runtime-grid">
            <div class="runtime-state-card">
              <div class="runtime-state-card__topline">
                <div>
                  <div class="text-subtitle-2">Sniffer</div>
                  <div class="text-caption text-medium-emphasis">
                    {{ snifferSummary }}
                  </div>
                </div>
                <v-chip size="small" :color="snifferChipColor" variant="tonal">
                  {{ snifferStatusLabel }}
                </v-chip>
              </div>
              <div class="runtime-state-card__body">
                <div class="runtime-stat">
                  <span class="runtime-stat__label">Packets seen</span>
                  <span class="runtime-stat__value">{{ snifferPacketsSeen }}</span>
                </div>
                <div class="runtime-stat">
                  <span class="runtime-stat__label">Interfaces</span>
                  <span class="runtime-stat__value">{{ snifferInterfacesLabel }}</span>
                </div>
              </div>
            </div>

            <div class="runtime-state-card runtime-state-card--warm">
              <div class="runtime-state-card__topline">
                <div>
                  <div class="text-subtitle-2">Honeypot</div>
                  <div class="text-caption text-medium-emphasis">
                    {{ honeypotSummary }}
                  </div>
                </div>
                <v-chip size="small" :color="honeypotChipColor" variant="tonal">
                  {{ honeypotStatusLabel }}
                </v-chip>
              </div>
              <div class="runtime-state-card__body">
                <div class="runtime-stat">
                  <span class="runtime-stat__label">Events seen</span>
                  <span class="runtime-stat__value">{{ honeypotPacketsSeen }}</span>
                </div>
                <div class="runtime-stat">
                  <span class="runtime-stat__label">Listeners</span>
                  <span class="runtime-stat__value">{{ honeypotListenersLabel }}</span>
                </div>
              </div>
            </div>
          </div>

          <v-alert
            v-if="snifferBlocked"
            type="error"
            variant="tonal"
            density="comfortable"
            class="mt-4"
          >
            {{ snifferErrorSummary }}
          </v-alert>
        </DataPanel>
      </v-col>

      <v-col cols="12" xl="5">
        <DataPanel
          title="Protocol Pressure"
          subtitle="Top observed protocols and quick entry points into the dedicated traffic views."
          v-model:live-enabled="liveRefreshEnabled"
          :loading="loading"
          :last-updated="lastUpdated"
          :live-refresh="true"
          @refresh="load"
        >
          <div class="d-flex flex-wrap ga-2">
            <v-btn color="primary" variant="flat" to="/sniffer">Open Sniffer</v-btn>
            <v-btn color="warning" variant="outlined" to="/honeypot">Open Honeypot</v-btn>
            <v-btn color="info" variant="outlined" to="/targets">Session Inventory</v-btn>
          </div>

          <v-divider class="my-4" />

          <div class="text-subtitle-2">Observed protocols</div>
          <div class="d-flex flex-wrap ga-2 mt-3">
            <v-chip
              v-for="item in protocolSeries"
              :key="item.label"
              size="small"
              variant="tonal"
              color="info"
            >
              {{ item.label.toUpperCase() }}: {{ item.value }}
            </v-chip>
            <span v-if="!protocolSeries.length" class="text-body-2 text-medium-emphasis">
              No packets recorded yet.
            </span>
          </div>

          <v-divider class="my-4" />

          <div class="text-subtitle-2">WebSocket clients</div>
          <div class="text-body-2 text-medium-emphasis mt-2">
            {{ wsClientCount }} dashboards connected to realtime updates.
          </div>
        </DataPanel>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="4">
        <EntityTablePanel
          title="Sessions"
          subtitle="Latest capture scopes and listener profiles."
          v-model:live-enabled="liveRefreshEnabled"
          :rows="recentTargets"
          :columns="targetColumns"
          :search-enabled="true"
          search-label="Search sessions"
          search-placeholder="Network, proto, interface..."
          :search-fields="targetSearchFields"
          :filter-definitions="targetFilterDefinitions"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          empty-text="No sessions configured"
          :page-size="6"
          @refresh="load"
        >
          <template #cell-status="{ value }">
            <v-chip size="small" :color="statusColor(value)" variant="tonal">
              {{ normalizeStatus(value) }}
            </v-chip>
          </template>
          <template #cell-actions="{ item }">
            <div class="target-actions">
              <v-btn
                size="x-small"
                color="success"
                variant="tonal"
                :disabled="loading || isActionLoading(item.id, 'start') || normalizeStatus(item.status) === 'active'"
                @click="runTargetAction(item, 'start')"
              >
                Start
              </v-btn>
              <v-btn
                size="x-small"
                color="warning"
                variant="tonal"
                :disabled="loading || isActionLoading(item.id, 'stop') || normalizeStatus(item.status) === 'stopped'"
                @click="runTargetAction(item, 'stop')"
              >
                Stop
              </v-btn>
            </div>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="8">
        <EntityTablePanel
          title="Latest Packets"
          subtitle="Newest captured frames from sniffer and honeypot sources."
          v-model:live-enabled="liveRefreshEnabled"
          :rows="recentPackets"
          :columns="packetColumns"
          :search-enabled="true"
          search-label="Search packets"
          search-placeholder="IP, port, flow, summary..."
          :search-fields="packetSearchFields"
          :filter-definitions="packetFilterDefinitions"
          :expandable-rows="true"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          empty-text="No packets visible"
          :page-size="8"
          @refresh="load"
        >
          <template #cell-updated_at="{ value }">
            {{ formatTimestamp(value) }}
          </template>
          <template #cell-interface="{ value }">
            <v-chip size="x-small" :color="interfaceChipColor(value)" variant="tonal">
              {{ value || "unknown" }}
            </v-chip>
          </template>
          <template #cell-proto="{ value }">
            <v-chip size="x-small" color="primary" variant="tonal">
              {{ String(value || "unknown").toUpperCase() }}
            </v-chip>
          </template>
          <template #cell-state="{ value }">
            <v-chip size="x-small" :color="statusColor(value)" variant="tonal">
              {{ value || "unknown" }}
            </v-chip>
          </template>
          <template #cell-source="{ item }">
            <div class="flow-cell">
              <span class="mono">{{ formatEndpoint(item.src_ip, item.src_port) }}</span>
            </div>
          </template>
          <template #cell-target="{ item }">
            <div class="flow-cell">
              <span class="mono">{{ formatEndpoint(item.dst_ip, item.dst_port) }}</span>
            </div>
          </template>
          <template #cell-size="{ item }">
            <span class="meta-cell">{{ buildPacketSizeSummary(item) }}</span>
          </template>
          <template #cell-summary="{ item }">
            <span class="summary-cell">{{ buildPacketSummary(item, 120) || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12">
        <EntityTablePanel
          title="Latest Responses"
          subtitle="Most recent payloads and banners decoded from captured traffic."
          v-model:live-enabled="liveRefreshEnabled"
          :rows="recentBanners"
          :columns="bannerColumns"
          :search-enabled="true"
          search-label="Search responses"
          search-placeholder="IP, port, response, flow..."
          :search-fields="bannerSearchFields"
          :filter-definitions="bannerFilterDefinitions"
          :expandable-rows="true"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          empty-text="No responses visible"
          :page-size="8"
          @refresh="load"
        >
          <template #cell-updated_at="{ value }">
            {{ formatTimestamp(value) }}
          </template>
          <template #cell-interface="{ value }">
            <v-chip size="x-small" :color="interfaceChipColor(value)" variant="tonal">
              {{ value || "unknown" }}
            </v-chip>
          </template>
          <template #cell-proto="{ value }">
            <v-chip size="x-small" color="primary" variant="tonal">
              {{ String(value || "unknown").toUpperCase() }}
            </v-chip>
          </template>
          <template #cell-state="{ value }">
            <v-chip size="x-small" :color="statusColor(value)" variant="tonal">
              {{ value || "unknown" }}
            </v-chip>
          </template>
          <template #cell-source="{ item }">
            <span class="mono">{{ formatEndpoint(item.src_ip, item.src_port) }}</span>
          </template>
          <template #cell-target="{ item }">
            <span class="mono">{{ formatEndpoint(item.dst_ip, item.dst_port) }}</span>
          </template>
          <template #cell-response_size="{ value }">
            <span class="meta-cell">{{ formatBytes(value) || "-" }}</span>
          </template>
          <template #cell-response_plain="{ item }">
            <span class="summary-cell">{{ buildResponseSummary(item, 160) || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>
    </v-row>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import {
  buildPacketSizeSummary,
  buildPacketSummary,
  buildResponseSummary,
  formatEndpoint,
  formatBytes,
  formatTimestamp,
  isHoneypotInterface,
} from "../utils/traffic";

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode", "scan_map_update"]);

export default {
  name: "DashboardView",
  components: {
    ViewHeader,
    DataPanel,
    EntityTablePanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: false,
      dashboard: {},
      analytics: {},
      packets: [],
      banners: [],
      actionLoading: {
        id: null,
        action: "",
      },
      targetColumns: [
        { key: "network", label: "Network" },
        { key: "proto", label: "Proto" },
        { key: "status", label: "Status" },
        { key: "interface", label: "Interface" },
        { key: "actions", label: "Actions" },
      ],
      targetSearchFields: ["network", "proto", "status", "interface", "type", "port_mode"],
      targetFilterDefinitions: [
        {
          key: "proto",
          label: "Proto",
          field: "proto",
          optionLabel: (value) => String(value || "").toUpperCase(),
        },
        {
          key: "status",
          label: "Status",
          field: "status",
        },
      ],
      packetColumns: [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Interface" },
        { key: "proto", label: "Proto" },
        { key: "state", label: "State" },
        { key: "source", label: "Source" },
        { key: "target", label: "Target" },
        { key: "size", label: "Size" },
        { key: "summary", label: "Summary" },
      ],
      packetSearchFields: [
        "updated_at",
        "interface",
        "proto",
        "state",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "length",
        "payload_len",
        "summary",
        "payload_text",
        "banner_text",
        "flow_key",
        "tcp_flags",
        "icmp_type",
        "icmp_code",
      ],
      packetFilterDefinitions: [
        {
          key: "proto",
          label: "Proto",
          field: "proto",
          optionLabel: (value) => String(value || "").toUpperCase(),
        },
        {
          key: "interface",
          label: "Interface",
          field: "interface",
        },
        {
          key: "state",
          label: "State",
          field: "state",
        },
      ],
      bannerColumns: [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Interface" },
        { key: "proto", label: "Proto" },
        { key: "state", label: "State" },
        { key: "source", label: "Source" },
        { key: "target", label: "Target" },
        { key: "response_size", label: "Size" },
        { key: "response_plain", label: "Response" },
      ],
      bannerSearchFields: [
        "updated_at",
        "interface",
        "proto",
        "state",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "response_size",
        "response_plain",
        "summary",
        "banner_text",
        "flow_key",
      ],
      bannerFilterDefinitions: [
        {
          key: "proto",
          label: "Proto",
          field: "proto",
          optionLabel: (value) => String(value || "").toUpperCase(),
        },
        {
          key: "interface",
          label: "Interface",
          field: "interface",
        },
        {
          key: "state",
          label: "State",
          field: "state",
        },
      ],
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    counts() {
      return this.dashboard && this.dashboard.counts ? this.dashboard.counts : {};
    },
    runtime() {
      const runtime = this.dashboard && this.dashboard.runtime ? this.dashboard.runtime : this.store.state.runtime;
      return runtime && typeof runtime === "object" ? runtime : {};
    },
    snifferRuntime() {
      return this.runtime.sniffer && typeof this.runtime.sniffer === "object" ? this.runtime.sniffer : {};
    },
    honeypotRuntime() {
      return this.runtime.honeypot && typeof this.runtime.honeypot === "object" ? this.runtime.honeypot : {};
    },
    metricCards() {
      const analyticsSummary = this.analytics.summary || {};
      return [
        {
          key: "sessions",
          label: "Sessions",
          value: Number(this.counts.count_targets || 0),
          caption: "Capture scopes and honeypot profiles",
          icon: "mdi-account-switch",
          colorClass: "text-primary",
        },
        {
          key: "packets",
          label: "Packets",
          value: Number(this.counts.count_ports || 0),
          caption: "Frames written into packet telemetry",
          icon: "mdi-ethernet",
          colorClass: "text-success",
        },
        {
          key: "responses",
          label: "Responses",
          value: Number(this.counts.count_banners || 0),
          caption: "Decoded payload and banner artifacts",
          icon: "mdi-server-network",
          colorClass: "text-info",
        },
        {
          key: "hosts",
          label: "Unique Hosts",
          value: Number(analyticsSummary.unique_hosts || 0),
          caption: "Distinct IPs seen across the capture set",
          icon: "mdi-lan-connect",
          colorClass: "text-warning",
        },
        {
          key: "protocols",
          label: "Protocols",
          value: this.protocolSeries.length,
          caption: "Observed protocol families",
          icon: "mdi-source-branch",
          colorClass: "text-secondary",
        },
        {
          key: "honeypot",
          label: "Honeypot Hits",
          value: this.honeypotPacketsSeen,
          caption: "Inbound events recorded by honeypot listeners",
          icon: "mdi-shield-bug",
          colorClass: "text-warning",
        },
      ];
    },
    protocolSeries() {
      return Array.isArray(this.analytics.ports_by_proto)
        ? this.analytics.ports_by_proto.slice(0, 8)
        : [];
    },
    wsClientCount() {
      const clients = this.dashboard && Array.isArray(this.dashboard.ws_clients) ? this.dashboard.ws_clients : [];
      return clients.length;
    },
    recentTargets() {
      const rows = this.dashboard && Array.isArray(this.dashboard.targets) ? this.dashboard.targets : [];
      return rows.slice(0, 6);
    },
    recentPackets() {
      return Array.isArray(this.packets) ? this.packets.slice(0, 8) : [];
    },
    recentBanners() {
      return Array.isArray(this.banners) ? this.banners.slice(0, 8) : [];
    },
    snifferBlocked() {
      return String(this.snifferRuntime.capture_state || "").trim().toLowerCase() === "blocked";
    },
    snifferStatusLabel() {
      if (this.snifferBlocked) return "Blocked";
      if (this.snifferRuntime.running) return "Running";
      return "Idle";
    },
    snifferChipColor() {
      if (this.snifferBlocked) return "error";
      if (this.snifferRuntime.running) return "success";
      return "secondary";
    },
    snifferPacketsSeen() {
      return Number(this.snifferRuntime.packets_seen || 0);
    },
    snifferInterfacesLabel() {
      const active = Array.isArray(this.snifferRuntime.interfaces) ? this.snifferRuntime.interfaces : [];
      const selected = Array.isArray(this.snifferRuntime.selected_interfaces)
        ? this.snifferRuntime.selected_interfaces
        : [];
      if (active.length === 1) return active[0];
      if (active.length > 1) return `${active.length} active`;
      if (selected.length === 1) return selected[0];
      if (selected.length > 1) return `${selected.length} selected`;
      return "all visible";
    },
    snifferSummary() {
      if (this.snifferBlocked) return this.snifferErrorSummary;
      if (this.snifferRuntime.running) return "Passive capture is running.";
      return `Ready on ${this.snifferInterfacesLabel}.`;
    },
    snifferErrorSummary() {
      const entries = this.snifferRuntime.errors && typeof this.snifferRuntime.errors === "object"
        ? Object.entries(this.snifferRuntime.errors)
        : [];
      if (!entries.length) return "Packet capture is blocked on the selected interfaces.";
      return entries
        .slice(0, 2)
        .map(([name, message]) => `${name}: ${message}`)
        .join(" | ");
    },
    honeypotPacketsSeen() {
      return Number(this.honeypotRuntime.packets_seen || 0);
    },
    honeypotStatusLabel() {
      if (this.honeypotRuntime.running) return "Running";
      return "Ready";
    },
    honeypotChipColor() {
      return this.honeypotRuntime.running ? "warning" : "secondary";
    },
    honeypotListenersLabel() {
      const listeners = Array.isArray(this.honeypotRuntime.listeners) ? this.honeypotRuntime.listeners : [];
      if (listeners.length === 1) return "1 listener";
      return `${listeners.length} listeners`;
    },
    honeypotSummary() {
      if (this.honeypotRuntime.running) return "Service emulation is accepting inbound traffic.";
      return "Ready to expose service listeners when started.";
    },
  },
  watch: {
    apiBase() {
      this.load();
    },
    liveRefreshEnabled(value) {
      if (!value && this.wsRefreshTimer) {
        clearTimeout(this.wsRefreshTimer);
        this.wsRefreshTimer = null;
      }
    },
  },
  mounted() {
    this.load();
    this.stopTableRefreshSubscription = this.store.subscribeTableRefresh(this.handleWsRefresh);
  },
  beforeUnmount() {
    if (this.wsRefreshTimer) {
      clearTimeout(this.wsRefreshTimer);
      this.wsRefreshTimer = null;
    }
    if (typeof this.stopTableRefreshSubscription === "function") {
      this.stopTableRefreshSubscription();
      this.stopTableRefreshSubscription = null;
    }
  },
  methods: {
    buildPacketSizeSummary,
    buildPacketSummary,
    buildResponseSummary,
    formatEndpoint,
    formatBytes,
    formatTimestamp,
    normalizeStatus(value) {
      const raw = String(value || "active").trim().toLowerCase();
      if (raw === "open" || raw === "active") return raw;
      if (raw === "filtered" || raw === "blocked") return raw;
      if (raw === "closed") return raw;
      if (raw === "restarting") return "restarting";
      if (raw === "stopped") return "stopped";
      return "active";
    },
    statusColor(value) {
      const status = this.normalizeStatus(value);
      if (status === "open" || status === "active") return "success";
      if (status === "restarting") return "info";
      if (status === "filtered" || status === "blocked" || status === "stopped") return "warning";
      if (status === "closed") return "error";
      return "warning";
    },
    interfaceChipColor(value) {
      return isHoneypotInterface(value) ? "warning" : "info";
    },
    isActionLoading(id, action) {
      return this.actionLoading.id === id && this.actionLoading.action === action;
    },
    runTargetAction(item, action) {
      const targetId = Number(item && item.id);
      if (!Number.isFinite(targetId) || targetId <= 0) {
        this.error = "Invalid session id";
        return Promise.resolve();
      }
      this.error = "";
      this.actionLoading.id = targetId;
      this.actionLoading.action = action;
      return this.store
        .fetchJsonPromise("/target/action/", {
          method: "POST",
          body: JSON.stringify({
            id: targetId,
            action,
            clean_results: false,
          }),
        })
        .then(() => this.load())
        .catch((err) => {
          this.error = err.message || `Failed to ${action} session`;
        })
        .finally(() => {
          this.actionLoading.id = null;
          this.actionLoading.action = "";
        });
    },
    handleWsRefresh(event) {
      if (!this.liveRefreshEnabled) return;
      const eventType = String((event && event.type) || "").trim().toLowerCase();
      if (!REFRESH_EVENT_TYPES.has(eventType)) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.load().catch(() => {
          // preserve current dashboard on transient realtime failures
        });
      }, 10000);
    },
    load() {
      this.loading = true;
      this.error = "";
      return Promise.allSettled([
        this.store.fetchJsonPromise("/api/dashboard/"),
        this.store.fetchJsonPromise("/api/charts/analytics"),
        this.store.fetchJsonPromise("/ports/?limit=12"),
        this.store.fetchJsonPromise("/banners/?limit=8"),
      ])
        .then(([dashboardRes, analyticsRes, packetsRes, bannersRes]) => {
          const errors = [];
          if (dashboardRes.status === "fulfilled") {
            this.dashboard = dashboardRes.value || {};
          } else {
            this.dashboard = {};
            errors.push((dashboardRes.reason && dashboardRes.reason.message) || "Failed to load dashboard snapshot");
          }
          if (analyticsRes.status === "fulfilled") {
            this.analytics = analyticsRes.value || {};
          } else {
            this.analytics = {};
            errors.push((analyticsRes.reason && analyticsRes.reason.message) || "Failed to load analytics");
          }
          if (packetsRes.status === "fulfilled") {
            this.packets = this.store.extractArray(packetsRes.value);
          } else {
            this.packets = [];
            errors.push((packetsRes.reason && packetsRes.reason.message) || "Failed to load packets");
          }
          if (bannersRes.status === "fulfilled") {
            this.banners = this.store.extractArray(bannersRes.value);
          } else {
            this.banners = [];
            errors.push((bannersRes.reason && bannersRes.reason.message) || "Failed to load responses");
          }
          this.lastUpdated = new Date().toLocaleTimeString();
          this.error = errors.join(" | ");
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.metric-card {
  border-radius: 16px;
}

.metric-icon {
  opacity: 0.92;
}

.runtime-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.runtime-state-card {
  padding: 16px;
  border-radius: 16px;
  border: 1px solid rgba(104, 184, 229, 0.16);
  background: linear-gradient(180deg, rgba(12, 21, 33, 0.88), rgba(8, 14, 23, 0.84));
}

.runtime-state-card--warm {
  border-color: rgba(246, 179, 87, 0.16);
  background: linear-gradient(180deg, rgba(32, 22, 11, 0.76), rgba(15, 13, 10, 0.82));
}

.runtime-state-card__topline {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.runtime-state-card__body {
  display: grid;
  gap: 10px;
  margin-top: 14px;
}

.runtime-stat {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 10px 12px;
  border-radius: 12px;
  background: rgba(4, 10, 18, 0.44);
}

.runtime-stat__label {
  color: rgba(176, 199, 220, 0.76);
  font-size: 0.8rem;
}

.runtime-stat__value {
  font-weight: 700;
}

.target-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.flow-cell {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.flow-cell__arrow {
  color: rgba(121, 213, 248, 0.9);
}

.mono {
  font-family: var(--font-mono);
}

.meta-cell {
  display: inline-block;
  max-width: 160px;
  overflow-wrap: anywhere;
}

.summary-cell {
  display: inline-block;
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (max-width: 1264px) {
  .runtime-grid {
    grid-template-columns: 1fr;
  }
}
</style>
