<template>
  <div>
    <ViewHeader
      overline="Detection"
      title="Monitors"
      description="Only traffic that matches an enabled monitor gets written to disk. Everything else is parsed, counted live, and discarded."
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

    <div class="d-flex justify-end mt-6 mb-3">
      <v-btn
        size="small"
        variant="text"
        color="primary"
        prepend-icon="mdi-cog-outline"
        to="/settings?section=detection"
      >
        Manage monitors &amp; persistence filter
      </v-btn>
    </div>

    <div class="d-flex align-center justify-space-between flex-wrap ga-2 mt-2 mb-3">
      <div>
        <div class="text-h6">Monitor Traffic</div>
        <div class="text-caption text-medium-emphasis">
          One table per monitor, generated automatically — expand any monitor to filter/search its
          matched packets and see its stats and charts.
        </div>
      </div>
    </div>

    <v-expansion-panels
      v-model="expandedMonitorPanel"
      variant="accordion"
      class="monitor-traffic-panels mb-6"
    >
      <v-expansion-panel
        v-for="monitor in monitors"
        :id="`monitor-row-${monitor.id}`"
        :key="monitor.id"
        :value="monitor.id"
      >
        <v-expansion-panel-title>
          <div class="d-flex align-center flex-wrap ga-2">
            <v-chip
              v-if="monitor.match_count > 0"
              size="x-small"
              color="info"
              variant="tonal"
              prepend-icon="mdi-table-row"
              class="match-count-chip"
            >
              {{ monitor.match_count.toLocaleString() }}
            </v-chip>
            <span class="font-weight-medium">{{ monitor.name }}</span>
            <v-chip size="x-small" :color="modeColor(monitor.mode)" variant="tonal">
              {{ modeLabel(monitor.mode) }}
            </v-chip>
            <v-chip size="x-small" :color="severityColor(monitor.action && monitor.action.severity)" variant="tonal">
              {{ (monitor.action && monitor.action.severity) || "info" }}
            </v-chip>
            <v-chip size="x-small" :color="monitor.source === 'builtin' ? 'secondary' : 'success'" variant="tonal">
              {{ monitor.source === "builtin" ? "Built-in" : "Custom" }}
            </v-chip>
            <v-chip size="x-small" :color="monitor.enabled ? 'success' : 'secondary'" variant="outlined">
              {{ monitor.enabled ? "Enabled" : "Disabled" }}
            </v-chip>
          </div>
        </v-expansion-panel-title>
        <v-expansion-panel-text>
          <MonitorMatchesPanel :monitor="monitor" />
        </v-expansion-panel-text>
      </v-expansion-panel>
    </v-expansion-panels>

    <EntityTablePanel
      title="Domains"
      subtitle="Domains observed via DNS lookups, HTTP Host headers, and TLS SNI. Only populated while the matching monitors are enabled."
      class="mt-6"
      v-model:live-enabled="liveRefreshEnabled"
      :live-refresh="true"
      :rows="domains"
      :columns="domainColumns"
      :loading="domainsLoading"
      :error="domainsError"
      :last-updated="domainsLastUpdated"
      search-enabled
      search-label="Search domains"
      search-placeholder="Domain, source, IP..."
      :page-size="25"
      empty-text="No domains observed yet"
      @refresh="loadDomains"
    >
      <template #cell-source="{ value }">
        <v-chip size="x-small" :color="domainSourceColor(value)" variant="tonal">
          {{ domainSourceLabel(value) }}
        </v-chip>
      </template>
      <template #cell-last_seen="{ value }">
        {{ formatTimestamp(value) }}
      </template>
    </EntityTablePanel>

    <EntityTablePanel
      title="Paths"
      subtitle="HTTP request paths observed on traffic that matched the HTTP requests monitor."
      class="mt-6"
      v-model:live-enabled="liveRefreshEnabled"
      :live-refresh="true"
      :rows="paths"
      :columns="pathColumns"
      :loading="pathsLoading"
      :error="pathsError"
      :last-updated="pathsLastUpdated"
      search-enabled
      search-label="Search paths"
      search-placeholder="Path, host, method, IP..."
      :page-size="25"
      empty-text="No HTTP paths observed yet"
      @refresh="loadPaths"
    >
      <template #cell-method="{ value }">
        <v-chip size="x-small" color="primary" variant="tonal">{{ value }}</v-chip>
      </template>
      <template #cell-last_seen="{ value }">
        {{ formatTimestamp(value) }}
      </template>
    </EntityTablePanel>

    <EntityTablePanel
      title="IPs"
      subtitle="Distinct source/destination IPs seen in stored (detected) traffic."
      class="mt-6 mb-6"
      v-model:live-enabled="liveRefreshEnabled"
      :live-refresh="true"
      :rows="ips"
      :columns="ipColumns"
      :loading="ipsLoading"
      :error="ipsError"
      :last-updated="ipsLastUpdated"
      search-enabled
      search-label="Search IPs"
      search-placeholder="IP address..."
      :page-size="25"
      empty-text="No IPs observed yet"
      @refresh="loadIps"
    >
      <template #cell-private="{ item }">
        <v-chip size="x-small" :color="item.private ? 'secondary' : 'warning'" variant="tonal">
          {{ item.private ? "Private" : "Public" }}
        </v-chip>
      </template>
      <template #cell-first_seen="{ value }">
        {{ formatTimestamp(value) }}
      </template>
      <template #cell-last_seen="{ value }">
        {{ formatTimestamp(value) }}
      </template>
    </EntityTablePanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import MonitorMatchesPanel from "../components/monitors/MonitorMatchesPanel.vue";
import { formatTimestamp, matchesSearch } from "../utils/traffic";

const DOMAIN_SOURCE_LABELS = {
  dns: "DNS",
  tls_sni: "TLS SNI",
  http_host: "HTTP Host",
};

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

export default {
  name: "MonitorsView",
  components: {
    ViewHeader,
    EntityTablePanel,
    MonitorMatchesPanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      monitors: [],
      domains: [],
      domainsLoading: false,
      domainsError: "",
      domainsLastUpdated: "",
      domainColumns: [
        { key: "name", label: "Domain" },
        { key: "source", label: "Source" },
        { key: "ip", label: "Last IP" },
        { key: "port", label: "Port" },
        { key: "proto", label: "Proto" },
        { key: "hit_count", label: "Hits" },
        { key: "last_seen", label: "Last seen" },
      ],
      paths: [],
      pathsLoading: false,
      pathsError: "",
      pathsLastUpdated: "",
      pathColumns: [
        { key: "method", label: "Method" },
        { key: "path", label: "Path" },
        { key: "host", label: "Host" },
        { key: "ip", label: "Last IP" },
        { key: "hit_count", label: "Hits" },
        { key: "last_seen", label: "Last seen" },
      ],
      ips: [],
      ipsLoading: false,
      ipsError: "",
      ipsLastUpdated: "",
      ipColumns: [
        { key: "ip", label: "IP" },
        { key: "private", label: "Scope", sortable: false },
        { key: "hit_count", label: "Hits" },
        { key: "first_seen", label: "First seen" },
        { key: "last_seen", label: "Last seen" },
      ],
      liveRefreshEnabled: true,
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
      expandedMonitorPanel: null,
    };
  },
  computed: {
    metricCards() {
      const monitors = this.monitors;
      const enabled = monitors.filter((item) => item.enabled).length;
      const builtin = monitors.filter((item) => item.source === "builtin").length;
      const custom = monitors.length - builtin;
      return [
        {
          key: "total",
          label: "Monitors",
          value: monitors.length,
          caption: "Total detection definitions",
          icon: "mdi-target-account",
          colorClass: "text-primary",
        },
        {
          key: "enabled",
          label: "Enabled",
          value: enabled,
          caption: "Actively gating persistence",
          icon: "mdi-shield-check-outline",
          colorClass: "text-success",
        },
        {
          key: "builtin",
          label: "Built-in",
          value: builtin,
          caption: "Curated defaults, toggle only",
          icon: "mdi-shield-star-outline",
          colorClass: "text-info",
        },
        {
          key: "custom",
          label: "Custom",
          value: custom,
          caption: "Your rule and regex monitors",
          icon: "mdi-shield-edit-outline",
          colorClass: "text-warning",
        },
      ];
    },
  },
  mounted() {
    this.load().then(() => this.focusMonitorFromQuery());
    this.loadDomains();
    this.loadPaths();
    this.loadIps();
    this.stopTableRefreshSubscription = this.store.subscribeTableRefresh(this.handleWsRefresh);
  },
  watch: {
    // Clicking a notification while already on /monitors changes the query
    // string without remounting this view, so mounted() alone won't catch it.
    "$route.query.monitor"(next) {
      if (next) this.focusMonitorFromQuery();
    },
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
    matchesSearch,
    formatTimestamp,
    handleWsRefresh(event) {
      if (!this.liveRefreshEnabled) return;
      const eventType = String((event && event.type) || "").trim().toLowerCase();
      if (!REFRESH_EVENT_TYPES.has(eventType)) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        const silent = { silent: true };
        Promise.allSettled([
          this.load(silent),
          this.loadDomains(silent),
          this.loadPaths(silent),
          this.loadIps(silent),
        ]).catch(() => {
          // keep current data on transient refresh errors
        });
      }, 10000);
    },
    domainSourceLabel(value) {
      return DOMAIN_SOURCE_LABELS[value] || value || "unknown";
    },
    domainSourceColor(value) {
      if (value === "dns") return "info";
      if (value === "tls_sni") return "success";
      if (value === "http_host") return "primary";
      return "secondary";
    },
    loadDomains(options = {}) {
      if (!options.silent) this.domainsLoading = true;
      this.domainsError = "";
      return this.store
        .listDomains({ limit: 500 })
        .then((payload) => {
          this.domains = this.store.extractArray(payload);
          this.domainsLastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.domains = [];
          this.domainsError = (err && err.message) || "Failed to load domains";
        })
        .finally(() => {
          this.domainsLoading = false;
        });
    },
    loadPaths(options = {}) {
      if (!options.silent) this.pathsLoading = true;
      this.pathsError = "";
      return this.store
        .listPaths({ limit: 500 })
        .then((payload) => {
          this.paths = this.store.extractArray(payload);
          this.pathsLastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.paths = [];
          this.pathsError = (err && err.message) || "Failed to load paths";
        })
        .finally(() => {
          this.pathsLoading = false;
        });
    },
    loadIps(options = {}) {
      if (!options.silent) this.ipsLoading = true;
      this.ipsError = "";
      return this.store
        .listIpCatalog({ limit: 500 })
        .then((payload) => {
          this.ips = this.store.extractArray(payload);
          this.ipsLastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.ips = [];
          this.ipsError = (err && err.message) || "Failed to load IPs";
        })
        .finally(() => {
          this.ipsLoading = false;
        });
    },
    severityColor(value) {
      const severity = String(value || "info").trim().toLowerCase();
      if (severity === "critical") return "error";
      if (severity === "high") return "error";
      if (severity === "medium") return "warning";
      if (severity === "low") return "info";
      return "secondary";
    },
    modeLabel(value) {
      const mode = String(value || "").trim().toLowerCase();
      if (mode === "regex") return "Regex";
      if (mode === "stateful") return "Stateful";
      return "Rule";
    },
    modeColor(value) {
      const mode = String(value || "").trim().toLowerCase();
      if (mode === "regex") return "info";
      if (mode === "stateful") return "warning";
      return "primary";
    },
    focusMonitorFromQuery() {
      const target = String((this.$route.query && this.$route.query.monitor) || "").trim();
      if (!target) return;
      const monitor = this.monitors.find((item) => item.id === target || item.name === target);
      if (!monitor) return;
      this.expandedMonitorPanel = monitor.id;
      this.$nextTick(() => {
        const el = document.getElementById(`monitor-row-${monitor.id}`);
        if (el && typeof el.scrollIntoView === "function") {
          el.scrollIntoView({ behavior: "smooth", block: "center" });
        }
      });
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return this.store
        .listMonitors()
        .then((payload) => {
          this.monitors = this.store.extractArray(payload);
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.monitors = [];
          this.error = (err && err.message) || "Failed to load monitors";
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.match-count-chip {
  font-variant-numeric: tabular-nums;
  font-weight: 700;
}

.metric-card {
  border-radius: 16px;
}

.metric-icon {
  opacity: 0.92;
}

.monitor-traffic-panels {
  border-radius: 16px;
  overflow: hidden;
}
</style>
