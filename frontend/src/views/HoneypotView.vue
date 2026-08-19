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

    <DataPanel
      title="Honeypot Engine"
      subtitle="Only one engine (Sniffer or Honeypot) runs at a time. Starting this one stops the other. Only activate honeypot mode where you're allowed to bind the listener ports."
      variant="tonal"
      collapsible
      :count="runtime.packets_seen || 0"
      count-label="events seen"
      :error="runtimeError"
      class="mt-6 mb-2 engine-card"
    >
      <template #header-actions>
        <v-chip size="small" :color="engineChipColor" variant="tonal" :prepend-icon="engineStatusIcon">
          {{ engineStatusLabel }}
        </v-chip>
        <v-btn
          size="small"
          :color="engineActionColor"
          variant="outlined"
          :prepend-icon="engineActionIcon"
          :loading="runtimeSubmitting"
          @click="toggleEngine"
        >
          {{ engineActionLabel }}
        </v-btn>
      </template>
    </DataPanel>

    <DataPanel
      title="Listeners"
      subtitle="Enable or disable individual listeners. A listener can never be edited or removed once created - only turned on or off - so the record of what was ever exposed stays intact."
      variant="tonal"
      collapsible
      :count="listeners.length"
      count-label="listeners"
      :error="listenersError"
      class="mt-4 mb-2 listeners-card"
    >
      <template #header-actions>
        <v-btn size="small" color="primary" variant="outlined" prepend-icon="mdi-plus" @click="openNewListenerDialog">
          New Listener
        </v-btn>
      </template>

      <v-text-field
        v-model.trim="listenerSearch"
        label="Search listeners"
        placeholder="proto, port, label, source..."
        prepend-inner-icon="mdi-magnify"
        clearable
        variant="outlined"
        density="comfortable"
        class="mb-3"
        hide-details
      />

      <v-data-table
        :headers="listenerHeaders"
        :items="listeners"
        :search="listenerSearch"
        :custom-filter="filterListenerRows"
        density="comfortable"
        items-per-page="10"
        no-data-text="No listeners yet."
        class="listeners-table"
      >
        <template v-slot:[`item.endpoint`]="{ item }">
          <span class="mono">{{ String(item.proto || "").toUpperCase() }}/{{ item.port }}</span>
        </template>
        <template v-slot:[`item.label`]="{ item }">
          {{ item.label || "-" }}
        </template>
        <template v-slot:[`item.source`]="{ item }">
          <v-chip size="x-small" :color="item.source === 'builtin' ? 'secondary' : 'info'" variant="tonal">
            {{ item.source }}
          </v-chip>
        </template>
        <template v-slot:[`item.running`]="{ item }">
          <v-chip
            size="x-small"
            :color="item.running ? 'success' : 'secondary'"
            variant="tonal"
            :prepend-icon="item.running ? 'mdi-check-circle-outline' : 'mdi-close-circle-outline'"
          >
            {{ item.running ? "Running" : "Stopped" }}
          </v-chip>
        </template>
        <template v-slot:[`item.enabled`]="{ item }">
          <v-switch
            :model-value="item.enabled"
            :loading="listenerTogglePending === item.id"
            :disabled="Boolean(listenerTogglePending)"
            density="compact"
            hide-details
            color="success"
            @update:model-value="(value) => toggleListener(item, value)"
          />
        </template>
      </v-data-table>
    </DataPanel>

    <MonitorMatchesPanel :monitor="honeypotHitsMonitor" class="mt-4 mb-2" />

    <v-dialog v-model="newListenerDialog" max-width="420">
      <v-card class="pa-4">
        <div class="text-h6 mb-3">New Listener</div>
        <div class="text-caption text-medium-emphasis mb-3">
          This can be enabled or disabled later, but never edited or removed - double-check the
          protocol and port before creating it.
        </div>
        <v-select
          v-model="newListener.proto"
          :items="['tcp', 'udp']"
          label="Protocol"
          variant="outlined"
          density="comfortable"
        />
        <v-text-field
          v-model.number="newListener.port"
          label="Port"
          type="number"
          variant="outlined"
          density="comfortable"
          :min="1"
          :max="65535"
        />
        <v-text-field
          v-model.trim="newListener.label"
          label="Label (optional)"
          variant="outlined"
          density="comfortable"
        />
        <v-alert v-if="newListenerError" type="error" variant="tonal" density="comfortable" class="mb-3">
          {{ newListenerError }}
        </v-alert>
        <div class="d-flex justify-end ga-2">
          <v-btn variant="text" @click="newListenerDialog = false">Cancel</v-btn>
          <v-btn color="primary" variant="flat" :loading="newListenerSubmitting" @click="createListener">
            Create
          </v-btn>
        </div>
      </v-card>
    </v-dialog>

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
      <v-chip size="small" color="warning" variant="tonal" prepend-icon="mdi-access-point-check">
        Listeners: {{ listenerCount }}
      </v-chip>
      <v-chip size="small" variant="outlined" prepend-icon="mdi-table-eye">
        Traffic rows: {{ filteredPackets.length }}
      </v-chip>
      <v-chip size="small" variant="outlined" prepend-icon="mdi-content-save-check-outline">
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
import DataPanel from "../components/ui/DataPanel.vue";
import MonitorMatchesPanel from "../components/monitors/MonitorMatchesPanel.vue";
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
    DataPanel,
    MonitorMatchesPanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: true,
      packets: [],
      banners: [],
      runtimeSubmitting: false,
      runtimeError: "",
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
      listeners: [],
      listenersError: "",
      listenerTogglePending: "",
      listenerSearch: "",
      listenerHeaders: [
        { title: "Listener", key: "endpoint", value: (item) => `${item.proto}/${item.port}` },
        { title: "Label", key: "label" },
        { title: "Source", key: "source" },
        { title: "Status", key: "running" },
        { title: "Enabled", key: "enabled", sortable: false },
      ],
      newListenerDialog: false,
      newListenerSubmitting: false,
      newListenerError: "",
      newListener: { proto: "tcp", port: null, label: "" },
    };
  },
  computed: {
    honeypotHitsMonitor() {
      // Not a real entry in the monitors catalog (honeypot traffic never
      // runs through evaluate_packet/AnomalyEngine) - just enough shape for
      // MonitorMatchesPanel to query /api/monitors/packets/?monitor_id=
      // builtin-honeypot-hit, the id honeypot.py tags every hit with.
      return { id: "builtin-honeypot-hit", name: "Honeypot hits" };
    },
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
    engineStatusLabel() {
      return this.runtime.running ? "Running" : "Stopped";
    },
    engineChipColor() {
      return this.runtime.running ? "success" : "secondary";
    },
    engineStatusIcon() {
      return this.runtime.running ? "mdi-play-circle-outline" : "mdi-stop-circle-outline";
    },
    engineActionLabel() {
      return this.runtime.running ? "Stop" : "Start";
    },
    engineActionColor() {
      return this.runtime.running ? "warning" : "primary";
    },
    engineActionIcon() {
      return this.runtime.running ? "mdi-stop" : "mdi-play";
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
    this.loadListeners();
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
    toggleEngine() {
      if (this.runtimeSubmitting) return;
      const action = this.runtime.running ? "stop" : "start";
      this.runtimeError = "";
      this.runtimeSubmitting = true;
      this.store
        .controlRuntimeMode("honeypot", action)
        .catch((err) => {
          this.runtimeError = (err && err.message) || `Failed to ${action} the honeypot`;
        })
        .finally(() => {
          this.runtimeSubmitting = false;
        });
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
          // keep current honeypot view on transient realtime failures
        });
        this.loadListeners().catch(() => {
          // keep current listener list on transient realtime failures
        });
      }, 10000);
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
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
    filterListenerRows(value, query, item) {
      const needle = String(query || "").trim().toLowerCase();
      if (!needle) return true;
      const raw = item && item.raw ? item.raw : item;
      const haystack = [raw.proto, raw.port, raw.label, raw.source, raw.running ? "running" : "stopped"]
        .map((part) => String(part == null ? "" : part).toLowerCase())
        .join(" ");
      return haystack.includes(needle);
    },
    loadListeners() {
      return this.store
        .listHoneypotListeners()
        .then((payload) => {
          this.listeners = this.store.extractArray(payload);
          this.listenersError = "";
        })
        .catch((err) => {
          this.listeners = [];
          this.listenersError = (err && err.message) || "Failed to load listeners";
        });
    },
    toggleListener(listener, value) {
      if (this.listenerTogglePending) return;
      this.listenerTogglePending = listener.id;
      this.listenersError = "";
      this.store
        .toggleHoneypotListenerEnabled(listener.id, value)
        .then((snapshot) => {
          this.listeners = this.store.extractArray(snapshot && snapshot.listeners);
        })
        .catch((err) => {
          this.listenersError = (err && err.message) || `Failed to ${value ? "enable" : "disable"} ${listener.id}`;
        })
        .finally(() => {
          this.listenerTogglePending = "";
        });
    },
    openNewListenerDialog() {
      this.newListener = { proto: "tcp", port: null, label: "" };
      this.newListenerError = "";
      this.newListenerDialog = true;
    },
    createListener() {
      const port = Number(this.newListener.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        this.newListenerError = "Port must be a whole number between 1 and 65535";
        return;
      }
      const listenerId = `${this.newListener.proto}/${port}`;
      if (this.listeners.some((item) => item.id === listenerId)) {
        this.newListenerError = `${listenerId} already exists`;
        return;
      }
      this.newListenerSubmitting = true;
      this.newListenerError = "";
      this.store
        .createHoneypotListener(this.newListener.proto, port, this.newListener.label)
        .then((snapshot) => {
          this.listeners = this.store.extractArray(snapshot && snapshot.listeners);
          this.newListenerDialog = false;
        })
        .catch((err) => {
          this.newListenerError = (err && err.message) || "Failed to create listener";
        })
        .finally(() => {
          this.newListenerSubmitting = false;
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
