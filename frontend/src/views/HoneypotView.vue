<template>
  <div>
    <ViewHeader
      overline="Active Defense"
      title="Honeypot"
      description="Inspect inbound traffic that reached honeypot listeners and review the responses emitted by those services."
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

    <v-alert v-if="error" type="error" variant="tonal" class="mt-6">
      {{ error }}
    </v-alert>

    <v-row dense class="mt-4">
      <v-col cols="12" md="5">
        <v-text-field
          v-model.trim="filters.query"
          label="Search honeypot traffic"
          name="honeypot_search"
          placeholder="IP, port, response, summary..."
          prepend-inner-icon="mdi-magnify"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" sm="6" md="3">
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
      <v-col cols="12" sm="6" md="4">
        <v-select
          v-model="filters.service"
          :items="serviceOptions"
          label="Service"
          item-title="label"
          item-value="value"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
    </v-row>

    <div class="d-flex flex-wrap ga-2 mt-2">
      <v-chip size="small" color="warning" variant="tonal">
        Listeners: {{ listenerCount }}
      </v-chip>
      <v-chip size="small" variant="outlined">
        Traffic rows: {{ filteredPackets.length }}
      </v-chip>
      <v-chip size="small" variant="outlined">
        Response rows: {{ filteredBanners.length }}
      </v-chip>
    </div>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="7">
        <EntityTablePanel
          title="Inbound Traffic"
          subtitle="Connections and datagrams that hit honeypot listeners."
          v-model:live-enabled="liveRefreshEnabled"
          :rows="filteredPackets"
          :columns="packetColumns"
          :expandable-rows="true"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :page-size="30"
          empty-text="No honeypot traffic recorded"
          @refresh="load"
        >
          <template #cell-updated_at="{ value }">
            {{ formatTimestamp(value) }}
          </template>
          <template #cell-interface="{ value }">
            <v-chip size="x-small" color="warning" variant="tonal">
              {{ value || "honeypot" }}
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
          <template #cell-size="{ item }">
            <span class="meta-cell">{{ buildPacketSizeSummary(item) }}</span>
          </template>
          <template #cell-flow_key="{ value }">
            <span class="mono flow-key" :title="value || '-'">{{ truncateMiddle(value, 10, 10) || "-" }}</span>
          </template>
          <template #cell-summary="{ item }">
            <span class="summary-cell">{{ buildPacketSummary(item, 170) || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="5">
        <EntityTablePanel
          title="Honeypot Responses"
          subtitle="Decoded payloads and replies emitted by honeypot services."
          v-model:live-enabled="liveRefreshEnabled"
          :rows="filteredBanners"
          :columns="bannerColumns"
          :expandable-rows="true"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :page-size="30"
          empty-text="No honeypot responses recorded"
          @refresh="load"
        >
          <template #cell-updated_at="{ value }">
            {{ formatTimestamp(value) }}
          </template>
          <template #cell-interface="{ value }">
            <v-chip size="x-small" color="warning" variant="tonal">
              {{ value || "honeypot" }}
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
            <span class="meta-cell">{{ formatSize(value) }}</span>
          </template>
          <template #cell-flow_key="{ value }">
            <span class="mono flow-key" :title="value || '-'">{{ truncateMiddle(value, 10, 10) || "-" }}</span>
          </template>
          <template #cell-response_plain="{ item }">
            <span class="summary-cell">{{ buildResponseSummary(item, 180) || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>
    </v-row>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import {
  buildPacketSizeSummary,
  buildPacketSummary,
  buildResponseSummary,
  formatEndpoint,
  formatTimestamp,
  formatBytes,
  hasOptionValue,
  matchesSearch,
  truncateMiddle,
  uniqueSorted,
} from "../utils/traffic";

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

export default {
  name: "HoneypotView",
  components: {
    ViewHeader,
    EntityTablePanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: false,
      packets: [],
      banners: [],
      filters: {
        query: "",
        proto: "",
        service: "",
      },
      packetColumns: [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Listener" },
        { key: "proto", label: "Proto" },
        { key: "state", label: "State" },
        { key: "source", label: "Source" },
        { key: "target", label: "Target" },
        { key: "size", label: "Size" },
        { key: "flow_key", label: "Flow" },
        { key: "summary", label: "Summary" },
      ],
      bannerColumns: [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Listener" },
        { key: "proto", label: "Proto" },
        { key: "state", label: "State" },
        { key: "source", label: "Source" },
        { key: "target", label: "Target" },
        { key: "response_size", label: "Size" },
        { key: "flow_key", label: "Flow" },
        { key: "response_plain", label: "Response" },
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
      return runtime.honeypot && typeof runtime.honeypot === "object" ? runtime.honeypot : {};
    },
    listenerCount() {
      const listeners = Array.isArray(this.runtime.listeners) ? this.runtime.listeners : [];
      return listeners.length;
    },
    metricCards() {
      const packets = this.packets;
      const sources = new Set(packets.map((item) => String(item.src_ip || "").trim()).filter(Boolean));
      const services = new Set(packets.map((item) => String(item.dst_port || "").trim()).filter(Boolean));
      const protocols = new Set(packets.map((item) => String(item.proto || "").trim()).filter(Boolean));
      return [
        {
          key: "events",
          label: "Traffic Hits",
          value: packets.length,
          caption: "Inbound events accepted by honeypot listeners",
          icon: "mdi-radar",
          colorClass: "text-warning",
        },
        {
          key: "responses",
          label: "Responses",
          value: this.banners.length,
          caption: "Decoded honeypot payload or banner rows",
          icon: "mdi-reply-all",
          colorClass: "text-info",
        },
        {
          key: "sources",
          label: "Source IPs",
          value: sources.size,
          caption: "Distinct remote addresses seen in this slice",
          icon: "mdi-ip-network",
          colorClass: "text-primary",
        },
        {
          key: "services",
          label: "Services",
          value: Math.max(services.size, protocols.size),
          caption: `${this.listenerCount} listeners currently configured`,
          icon: "mdi-server-security",
          colorClass: "text-success",
        },
      ];
    },
    protocolOptions() {
      const values = uniqueSorted([
        ...this.packets.map((item) => item.proto),
        ...this.banners.map((item) => item.proto),
      ]);
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value.toUpperCase(), value }))];
    },
    serviceOptions() {
      const values = uniqueSorted(
        this.packets.map((item) => String(item.dst_port || item.port || "").trim()).filter(Boolean)
      );
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: `Port ${value}`, value }))];
    },
    filteredPackets() {
      const query = String(this.filters.query || "").trim().toLowerCase();
      const proto = String(this.filters.proto || "").trim().toLowerCase();
      const service = String(this.filters.service || "").trim();
      return this.packets.filter((item) => {
        if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
        if (service && String(item.dst_port || item.port || "").trim() !== service) return false;
        return matchesSearch(query, [
          item.interface,
          item.proto,
          item.src_ip,
          item.dst_ip,
          item.src_port,
          item.dst_port,
          item.state,
          item.flow_key,
          item.summary,
          item.banner_text,
          item.payload_text,
          item.payload_hex,
        ]);
      });
    },
    filteredBanners() {
      const query = String(this.filters.query || "").trim().toLowerCase();
      const proto = String(this.filters.proto || "").trim().toLowerCase();
      const service = String(this.filters.service || "").trim();
      return this.banners.filter((item) => {
        if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
        if (service && String(item.port || item.dst_port || "").trim() !== service) return false;
        return matchesSearch(query, [
          item.interface,
          item.proto,
          item.src_ip,
          item.dst_ip,
          item.src_port,
          item.dst_port,
          item.state,
          item.flow_key,
          item.response_size,
          item.response_plain,
          item.summary,
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
    buildPacketSizeSummary,
    buildPacketSummary,
    buildResponseSummary,
    formatEndpoint,
    formatTimestamp,
    truncateMiddle,
    syncFilters() {
      if (!hasOptionValue(this.protocolOptions, this.filters.proto)) this.filters.proto = "";
      if (!hasOptionValue(this.serviceOptions, this.filters.service)) this.filters.service = "";
    },
    formatSize(value) {
      return formatBytes(value) || "-";
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
        this.load().catch(() => {
          // keep current honeypot view on transient realtime failures
        });
      }, 10000);
    },
    load() {
      this.loading = true;
      this.error = "";
      return Promise.allSettled([
        this.store.fetchJsonPromise("/ports/?mode=honeypot&limit=400"),
        this.store.fetchJsonPromise("/banners/?mode=honeypot&limit=250"),
        this.store.initRuntime(),
      ])
        .then(([packetsRes, bannersRes]) => {
          const errors = [];
          if (packetsRes.status === "fulfilled") {
            this.packets = this.store.extractArray(packetsRes.value);
          } else {
            this.packets = [];
            errors.push((packetsRes.reason && packetsRes.reason.message) || "Failed to load honeypot traffic");
          }
          if (bannersRes.status === "fulfilled") {
            this.banners = this.store.extractArray(bannersRes.value);
          } else {
            this.banners = [];
            errors.push((bannersRes.reason && bannersRes.reason.message) || "Failed to load honeypot responses");
          }
          this.error = errors.join(" | ");
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

.metric-icon {
  opacity: 0.92;
}

.mono {
  font-family: var(--font-mono);
}

.meta-cell {
  display: inline-block;
  max-width: 160px;
  overflow-wrap: anywhere;
}

.flow-key {
  display: inline-block;
  max-width: 170px;
}

.summary-cell {
  display: inline-block;
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
