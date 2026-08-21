<template>
  <div>
    <ViewHeader
      overline="Telemetry"
      title="Sniffer"
      description="Inspect every captured packet, choose which interfaces to listen on, and filter by protocol, direction, and state."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-row dense>
      <v-col v-for="metric in metricCards" :key="metric.key" cols="12" sm="6" xl="3">
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

    <v-alert
      v-if="snifferBlocked"
      type="error"
      variant="tonal"
      class="mt-6"
    >
      {{ snifferErrorSummary }}
    </v-alert>

    <v-alert v-if="error" type="error" variant="tonal" class="mt-6">
      {{ error }}
    </v-alert>

    <div class="mt-6">
      <v-row dense class="mb-3">
        <v-col cols="12" md="4">
          <v-text-field
            v-model.trim="filters.query"
            label="Search packets"
            name="sniffer_packet_search"
            placeholder="IP, port, payload, summary..."
            prepend-inner-icon="mdi-magnify"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" sm="6" md="2">
          <v-select
            v-model="filters.proto"
            :items="protocolOptions"
            label="Protocol"
            item-title="label"
            item-value="value"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" sm="6" md="2">
          <v-select
            v-model="filters.interface"
            :items="interfaceOptions"
            label="Interface"
            item-title="label"
            item-value="value"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" sm="6" md="2">
          <v-select
            v-model="filters.direction"
            :items="directionOptions"
            label="Direction"
            item-title="label"
            item-value="value"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" sm="6" md="2">
          <v-select
            v-model="filters.state"
            :items="stateOptions"
            label="State"
            item-title="label"
            item-value="value"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
      </v-row>

      <div class="d-flex flex-wrap ga-2 mb-4">
        <v-chip size="small" variant="tonal" color="info" prepend-icon="mdi-lan-check">
          Selected: {{ selectedInterfacesLabel }}
        </v-chip>
        <v-chip size="small" variant="outlined" prepend-icon="mdi-access-point-network">
          Active interfaces: {{ activeInterfacesLabel }}
        </v-chip>
        <v-chip size="small" variant="outlined" prepend-icon="mdi-table-eye">
          Visible rows: {{ filteredPackets.length }}
        </v-chip>
        <v-chip size="small" variant="outlined" color="info" prepend-icon="mdi-download-network-outline">
          Captured: {{ runtime.packets_seen || 0 }}
        </v-chip>
        <v-chip size="small" variant="outlined" color="success" prepend-icon="mdi-database-check">
          Stored (detected): {{ runtime.packets_stored || 0 }}
        </v-chip>
        <v-btn
          size="small"
          variant="text"
          color="primary"
          prepend-icon="mdi-target-account"
          to="/monitors"
        >
          View detection monitors
        </v-btn>
        <v-btn
          size="small"
          variant="text"
          color="primary"
          prepend-icon="mdi-cog-outline"
          to="/settings?section=capture"
        >
          Configure interfaces
        </v-btn>
      </div>

      <DataPanel
        title="Sniffer Engine"
        subtitle="Only one engine runs at a time. Starting this one stops the honeypot."
        variant="tonal"
        collapsible
        :count="runtime.packets_seen || 0"
        count-label="packets seen"
        :error="runtimeError"
        class="mb-4 engine-card"
      >
        <template #header-actions>
          <v-chip size="small" :color="engineChipColor" variant="tonal" :prepend-icon="engineStatusIcon">
            {{ engineStatusLabel }}
          </v-chip>
        </template>
      </DataPanel>

      <EntityTablePanel
        title="Packets"
        subtitle="Newest packet rows emitted by the passive sniffer."
        v-model:live-enabled="liveRefreshEnabled"
        :rows="filteredPackets"
        :columns="columns"
        :expandable-rows="true"
        :loading="loading"
        :error="error"
        :last-updated="lastUpdated"
        :live-refresh="true"
        :page-size="40"
        empty-text="No sniffer packets available"
        @refresh="load"
      >
        <template #cell-updated_at="{ value }">
          {{ formatTimestamp(value) }}
        </template>
        <template #cell-interface="{ value }">
          <v-chip size="x-small" color="info" variant="tonal">
            {{ value || "unknown" }}
          </v-chip>
        </template>
        <template #cell-proto="{ value }">
          <v-chip size="x-small" color="primary" variant="tonal">
            {{ String(value || "unknown").toUpperCase() }}
          </v-chip>
        </template>
        <template #cell-direction="{ value }">
          <v-chip
            size="x-small"
            :color="String(value || '').trim().toLowerCase() === 'inbound' ? 'warning' : 'success'"
            variant="tonal"
          >
            {{ value || "unknown" }}
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
        <template #cell-size="{ item }">
          <span class="meta-cell">{{ buildPacketSizeSummary(item) }}</span>
        </template>
        <template #cell-route="{ item }">
          <span class="meta-cell">{{ buildPacketRouteSummary(item) }}</span>
        </template>
        <template #cell-flow_key="{ value }">
          <span class="mono flow-key" :title="value || '-'">{{ truncateMiddle(value, 10, 10) || "-" }}</span>
        </template>
        <template #cell-detail="{ item }">
          <span class="detail-cell">{{ buildPacketDetail(item) }}</span>
        </template>
        <template #cell-summary="{ item }">
          <span class="summary-cell">{{ buildPacketSummary(item, 180) || "-" }}</span>
        </template>
      </EntityTablePanel>
    </div>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import {
  buildPacketDetail,
  buildPacketRouteSummary,
  buildPacketSizeSummary,
  buildPacketSummary,
  formatEndpoint,
  formatTimestamp,
  hasOptionValue,
  matchesSearch,
  truncateMiddle,
  uniqueSorted,
} from "../utils/traffic";

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

export default {
  name: "SnifferView",
  components: {
    ViewHeader,
    EntityTablePanel,
    DataPanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: true,
      packets: [],
      runtimeError: "",
      filters: {
        query: "",
        proto: "",
        interface: "",
        direction: "",
        state: "",
      },
      columns: [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Interface" },
        { key: "proto", label: "Proto" },
        { key: "direction", label: "Direction" },
        { key: "state", label: "State" },
        { key: "source", label: "Source" },
        { key: "target", label: "Target" },
        { key: "size", label: "Size" },
        { key: "route", label: "Network" },
        { key: "flow_key", label: "Flow" },
        { key: "detail", label: "Signal" },
        { key: "summary", label: "Summary" },
      ],
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    runtime() {
      const runtime = this.store.state.runtime || {};
      return runtime.sniffer && typeof runtime.sniffer === "object" ? runtime.sniffer : {};
    },
    snifferBlocked() {
      return String(this.runtime.capture_state || "").trim().toLowerCase() === "blocked";
    },
    engineStatusLabel() {
      if (this.snifferBlocked) return "Blocked";
      if (this.runtime.running) return "Running";
      return "Stopped";
    },
    engineChipColor() {
      if (this.snifferBlocked) return "error";
      if (this.runtime.running) return "success";
      return "secondary";
    },
    engineStatusIcon() {
      if (this.snifferBlocked) return "mdi-alert-circle-outline";
      if (this.runtime.running) return "mdi-play-circle-outline";
      return "mdi-stop-circle-outline";
    },
    snifferErrorSummary() {
      const entries = this.runtime.errors && typeof this.runtime.errors === "object"
        ? Object.entries(this.runtime.errors)
        : [];
      if (!entries.length) return "Packet capture is blocked on the selected interfaces.";
      return entries
        .slice(0, 2)
        .map(([name, message]) => `${name}: ${message}`)
        .join(" | ");
    },
    metricCards() {
      const packets = this.packets;
      const protocols = new Set(packets.map((item) => String(item.proto || "").trim()).filter(Boolean));
      const interfaces = new Set(packets.map((item) => String(item.interface || "").trim()).filter(Boolean));
      const withPayload = packets.filter((item) => String(item.payload_text || item.banner_text || "").trim()).length;
      const inbound = packets.filter((item) => String(item.direction || "").trim().toLowerCase() === "inbound").length;
      return [
        {
          key: "packets",
          label: "Packets",
          value: packets.length,
          caption: "Latest sniffer rows loaded into the grid",
          icon: "mdi-ethernet",
          colorClass: "text-success",
        },
        {
          key: "protocols",
          label: "Protocols",
          value: protocols.size,
          caption: "Observed protocol families in this slice",
          icon: "mdi-source-branch",
          colorClass: "text-info",
        },
        {
          key: "interfaces",
          label: "Interfaces",
          value: interfaces.size,
          caption: "Interfaces currently represented in rows",
          icon: "mdi-lan",
          colorClass: "text-primary",
        },
        {
          key: "payloads",
          label: "Payload Rows",
          value: withPayload,
          caption: `${inbound} inbound packets in the current slice`,
          icon: "mdi-text-box-search",
          colorClass: "text-warning",
        },
      ];
    },
    protocolOptions() {
      const values = uniqueSorted(this.packets.map((item) => item.proto));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value.toUpperCase(), value }))];
    },
    interfaceOptions() {
      const values = uniqueSorted(this.packets.map((item) => item.interface));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    directionOptions() {
      const values = uniqueSorted(this.packets.map((item) => item.direction));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    stateOptions() {
      const values = uniqueSorted(this.packets.map((item) => item.state));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    selectedInterfacesLabel() {
      const values = Array.isArray(this.runtime.selected_interfaces) ? this.runtime.selected_interfaces : [];
      if (!values.length) return "all visible";
      return values.join(", ");
    },
    activeInterfacesLabel() {
      const values = Array.isArray(this.runtime.interfaces) ? this.runtime.interfaces : [];
      if (!values.length) return "none";
      if (values.length === 1) return values[0];
      return `${values.length} active`;
    },
    filteredPackets() {
      const query = String(this.filters.query || "").trim().toLowerCase();
      const proto = String(this.filters.proto || "").trim().toLowerCase();
      const interfaceName = String(this.filters.interface || "").trim().toLowerCase();
      const direction = String(this.filters.direction || "").trim().toLowerCase();
      const state = String(this.filters.state || "").trim().toLowerCase();
      return this.packets.filter((item) => {
        if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
        if (interfaceName && String(item.interface || "").trim().toLowerCase() !== interfaceName) return false;
        if (direction && String(item.direction || "").trim().toLowerCase() !== direction) return false;
        if (state && String(item.state || "").trim().toLowerCase() !== state) return false;
        return matchesSearch(query, [
          item.interface,
          item.proto,
          item.direction,
          item.state,
          item.scan_state,
          item.src_ip,
          item.dst_ip,
          item.src_port,
          item.dst_port,
          item.flow_key,
          item.eth_src,
          item.eth_dst,
          item.ttl,
          item.hop_limit,
          item.summary,
          item.banner_text,
          item.payload_text,
          item.payload_hex,
          item.tcp_flags,
          item.tags || [],
          item.rule_hits || [],
        ]);
      });
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
    buildPacketDetail,
    buildPacketRouteSummary,
    buildPacketSizeSummary,
    buildPacketSummary,
    formatEndpoint,
    formatTimestamp,
    truncateMiddle,
    syncFilters() {
      if (!hasOptionValue(this.protocolOptions, this.filters.proto)) this.filters.proto = "";
      if (!hasOptionValue(this.interfaceOptions, this.filters.interface)) this.filters.interface = "";
      if (!hasOptionValue(this.directionOptions, this.filters.direction)) this.filters.direction = "";
      if (!hasOptionValue(this.stateOptions, this.filters.state)) this.filters.state = "";
    },
    statusColor(value) {
      const state = String(value || "").trim().toLowerCase();
      if (state === "open" || state === "active") return "success";
      if (state === "filtered" || state === "blocked") return "warning";
      if (state === "closed") return "error";
      return "secondary";
    },
    handleWsRefresh(event) {
      if (!this.liveRefreshEnabled) return;
      const eventType = String((event && event.type) || "").trim().toLowerCase();
      if (!REFRESH_EVENT_TYPES.has(eventType)) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.load({ silent: true }).catch(() => {
          // keep the current table on transient refresh errors
        });
      }, 10000);
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return Promise.allSettled([
        this.store.fetchJsonPromise("/ports/?mode=sniffer&limit=600"),
        this.store.initRuntime(),
      ])
        .then(([packetsRes]) => {
          if (packetsRes.status === "fulfilled") {
            this.packets = this.store.extractArray(packetsRes.value);
            this.error = "";
          } else {
            this.packets = [];
            this.error = (packetsRes.reason && packetsRes.reason.message) || "Failed to load sniffer packets";
          }
          this.syncFilters();
          this.lastUpdated = new Date().toLocaleTimeString();
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

.engine-card {
  border-radius: 16px;
}

.metric-icon {
  opacity: 0.92;
}

.mono {
  font-family: var(--font-mono);
}

.meta-cell,
.detail-cell {
  display: inline-block;
  max-width: 180px;
  overflow-wrap: anywhere;
}

.flow-key {
  display: inline-block;
  max-width: 180px;
}

.summary-cell {
  display: inline-block;
  max-width: 480px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

</style>
