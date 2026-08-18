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
    <v-alert v-if="configError" type="error" variant="tonal" class="mt-4">
      {{ configError }}
    </v-alert>

    <v-card variant="tonal" class="pa-4 mt-6 mb-4 filter-card">
      <div class="d-flex align-start justify-space-between flex-wrap ga-3">
        <div>
          <div class="text-subtitle-2 font-weight-medium">Store only detected traffic</div>
          <div class="text-caption text-medium-emphasis mt-1">
            When enabled (recommended), packets that don't match any enabled monitor are never
            written to SQLite — they're still counted live but not persisted or shown in
            history/analytics. Turn this off to fall back to persisting everything captured.
          </div>
        </div>
        <v-switch
          :model-value="filterEnabled"
          :loading="configSubmitting"
          color="primary"
          hide-details
          inset
          @update:model-value="toggleFilter"
        />
      </div>
    </v-card>

    <div class="d-flex justify-end mb-3">
      <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreateDialog">
        New monitor
      </v-btn>
    </div>

    <EntityTablePanel
      title="Detection monitors"
      subtitle="Built-in monitors are read-only. Custom monitors can be edited or removed. Each monitor's own traffic table is below, under Monitor Traffic."
      v-model:live-enabled="liveRefreshEnabled"
      :live-refresh="true"
      :rows="monitors"
      :columns="columns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      search-enabled
      search-label="Search monitors"
      search-placeholder="Name, tag, description..."
      :page-size="25"
      empty-text="No monitors defined yet"
      @refresh="load"
    >
      <template #cell-mode="{ value }">
        <v-chip size="x-small" :color="modeColor(value)" variant="tonal">
          {{ modeLabel(value) }}
        </v-chip>
      </template>
      <template #cell-severity="{ item }">
        <v-chip size="x-small" :color="severityColor(item.action && item.action.severity)" variant="tonal">
          {{ (item.action && item.action.severity) || "info" }}
        </v-chip>
      </template>
      <template #cell-match_summary="{ item }">
        <span class="match-summary">{{ matchSummary(item) }}</span>
      </template>
      <template #cell-source="{ item }">
        <v-chip size="x-small" :color="item.source === 'builtin' ? 'secondary' : 'success'" variant="tonal">
          {{ item.source === "builtin" ? "Built-in" : "Custom" }}
        </v-chip>
      </template>
      <template #cell-enabled="{ item }">
        <v-switch
          :model-value="item.enabled"
          :disabled="item.source === 'builtin' || isBusy(item.id)"
          color="primary"
          density="compact"
          hide-details
          inset
          @update:model-value="(value) => toggleEnabled(item, value)"
        />
      </template>
      <template #cell-actions="{ item }">
        <div class="row-actions">
          <v-btn
            v-if="item.source !== 'builtin'"
            size="small"
            variant="tonal"
            color="primary"
            prepend-icon="mdi-pencil"
            :disabled="isBusy(item.id)"
            @click="openEditDialog(item)"
          >
            Edit
          </v-btn>
          <v-btn
            v-if="item.source !== 'builtin'"
            size="small"
            variant="tonal"
            color="error"
            prepend-icon="mdi-delete"
            :loading="isBusy(item.id)"
            @click="removeMonitor(item)"
          >
            Delete
          </v-btn>
        </div>
      </template>
    </EntityTablePanel>

    <div class="d-flex align-center justify-space-between flex-wrap ga-2 mt-6 mb-3">
      <div>
        <div class="text-h6">Monitor Traffic</div>
        <div class="text-caption text-medium-emphasis">
          One table per monitor, generated automatically — expand any monitor to filter/search its
          matched packets and see its stats and charts.
        </div>
      </div>
    </div>

    <v-expansion-panels variant="accordion" class="monitor-traffic-panels mb-6">
      <v-expansion-panel v-for="monitor in monitors" :key="monitor.id">
        <v-expansion-panel-title>
          <div class="d-flex align-center flex-wrap ga-2">
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

    <v-dialog v-model="dialogOpen" max-width="720">
      <v-card rounded="xl" class="pa-2">
        <v-card-title class="text-h6">
          {{ editingId ? "Edit monitor" : "New monitor" }}
        </v-card-title>
        <v-card-text>
          <v-alert v-if="formError" type="error" variant="tonal" density="comfortable" class="mb-4">
            {{ formError }}
          </v-alert>

          <v-row dense>
            <v-col cols="12" md="8">
              <v-text-field v-model.trim="form.name" label="Name" variant="outlined" density="comfortable" />
            </v-col>
            <v-col cols="12" md="4">
              <v-text-field
                v-model.number="form.priority"
                type="number"
                label="Priority"
                hint="Lower runs first"
                persistent-hint
                variant="outlined"
                density="comfortable"
              />
            </v-col>
            <v-col cols="12">
              <v-text-field
                v-model.trim="form.description"
                label="Description"
                variant="outlined"
                density="comfortable"
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-select
                v-model="form.severity"
                :items="severityOptions"
                label="Severity"
                variant="outlined"
                density="comfortable"
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-text-field
                v-model.trim="form.tag"
                label="Tag"
                hint="Short label attached to stored packets"
                persistent-hint
                variant="outlined"
                density="comfortable"
              />
            </v-col>
          </v-row>

          <v-btn-toggle v-model="form.mode" mandatory color="primary" class="mode-toggle my-4">
            <v-btn value="rule">Rule builder</v-btn>
            <v-btn value="regex">Regex</v-btn>
          </v-btn-toggle>

          <div v-if="form.mode === 'rule'">
            <v-row dense>
              <v-col cols="12" sm="6">
                <v-select
                  v-model="form.protocols"
                  :items="protocolOptions"
                  label="Protocols"
                  multiple
                  chips
                  closable-chips
                  clearable
                  variant="outlined"
                  density="comfortable"
                />
              </v-col>
              <v-col cols="12" sm="6">
                <v-combobox
                  v-model="form.ports"
                  label="Ports"
                  hint="Matches source or destination port"
                  persistent-hint
                  multiple
                  chips
                  closable-chips
                  clearable
                  variant="outlined"
                  density="comfortable"
                />
              </v-col>
              <v-col cols="12">
                <v-combobox
                  v-model="form.payloadContains"
                  label="Payload contains"
                  hint="Case-insensitive plain-text substrings"
                  persistent-hint
                  multiple
                  chips
                  closable-chips
                  clearable
                  variant="outlined"
                  density="comfortable"
                />
              </v-col>
              <v-col cols="12" sm="6">
                <v-text-field
                  v-model.number="form.minLength"
                  type="number"
                  label="Min packet length"
                  variant="outlined"
                  density="comfortable"
                />
              </v-col>
              <v-col cols="12" sm="6">
                <v-text-field
                  v-model.number="form.maxLength"
                  type="number"
                  label="Max packet length"
                  variant="outlined"
                  density="comfortable"
                />
              </v-col>
            </v-row>
          </div>

          <div v-else>
            <v-combobox
              v-model="form.payloadRegex"
              label="Regex patterns"
              hint="Enter, then press Enter to add another pattern. Any pattern matching flags this packet."
              persistent-hint
              multiple
              chips
              closable-chips
              clearable
              variant="outlined"
              density="comfortable"
              :error-messages="regexErrors"
            />
          </div>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="dialogOpen = false">Cancel</v-btn>
          <v-btn color="primary" variant="tonal" :loading="formSubmitting" @click="submitForm">
            Save monitor
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
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

const PROTOCOL_OPTIONS = ["tcp", "udp", "icmp", "icmpv6", "arp"];
const SEVERITY_OPTIONS = ["info", "low", "medium", "high"];
const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

function emptyForm() {
  return {
    name: "",
    description: "",
    priority: 100,
    severity: "medium",
    tag: "",
    mode: "rule",
    protocols: [],
    ports: [],
    payloadContains: [],
    minLength: null,
    maxLength: null,
    payloadRegex: [],
  };
}

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
      filterEnabled: true,
      configSubmitting: false,
      configError: "",
      busyIds: {},
      dialogOpen: false,
      editingId: "",
      form: emptyForm(),
      formError: "",
      formSubmitting: false,
      protocolOptions: PROTOCOL_OPTIONS,
      severityOptions: SEVERITY_OPTIONS,
      columns: [
        { key: "name", label: "Name" },
        { key: "mode", label: "Mode" },
        { key: "match_summary", label: "Match", sortable: false },
        { key: "severity", label: "Severity" },
        { key: "source", label: "Source" },
        { key: "enabled", label: "Enabled", sortable: false },
        { key: "actions", label: "", sortable: false, width: 200 },
      ],
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
          caption: "Curated defaults, read-only",
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
    regexErrors() {
      const invalid = (this.form.payloadRegex || []).filter((pattern) => !this.isValidRegex(pattern));
      return invalid.length ? [`Invalid regex: ${invalid.join(", ")}`] : [];
    },
  },
  mounted() {
    this.load();
    this.loadDomains();
    this.loadPaths();
    this.loadIps();
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
    isBusy(id) {
      return Boolean(this.busyIds[id]);
    },
    setBusy(id, value) {
      this.busyIds = { ...this.busyIds, [id]: value };
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
    matchSummary(item) {
      const match = item.match || {};
      const parts = [];
      if (match.protocols && match.protocols.length) parts.push(match.protocols.join("/").toUpperCase());
      if (match.ports && match.ports.length) parts.push(`ports ${match.ports.join(",")}`);
      if (match.eth_types && match.eth_types.length) {
        parts.push(`eth 0x${match.eth_types.map((value) => Number(value).toString(16)).join(",0x")}`);
      }
      if (match.payload_contains && match.payload_contains.length) {
        parts.push(`contains "${match.payload_contains.join('", "')}"`);
      }
      if (match.payload_regex && match.payload_regex.length) {
        parts.push(`regex ${match.payload_regex.length === 1 ? match.payload_regex[0] : `${match.payload_regex.length} patterns`}`);
      }
      if (match.min_length) parts.push(`>=${match.min_length}B`);
      if (match.max_length) parts.push(`<=${match.max_length}B`);
      return parts.length ? parts.join(" · ") : "-";
    },
    isValidRegex(pattern) {
      try {
        new RegExp(pattern);
        return true;
      } catch {
        return false;
      }
    },
    toggleFilter(value) {
      this.configSubmitting = true;
      this.configError = "";
      this.store
        .setMonitorConfig({ filter_enabled: Boolean(value) })
        .then((payload) => {
          this.filterEnabled = Boolean(payload && payload.filter_enabled);
        })
        .catch((err) => {
          this.configError = (err && err.message) || "Failed to update the persistence filter";
        })
        .finally(() => {
          this.configSubmitting = false;
        });
    },
    toggleEnabled(item, value) {
      if (item.source === "builtin") return;
      this.setBusy(item.id, true);
      this.store
        .saveMonitor({ ...this.toPayload(item), id: item.id, enabled: Boolean(value) })
        .then(() => this.load())
        .catch((err) => {
          this.error = (err && err.message) || "Failed to update monitor";
        })
        .finally(() => {
          this.setBusy(item.id, false);
        });
    },
    toPayload(item) {
      return {
        name: item.name,
        description: item.description,
        priority: item.priority,
        enabled: item.enabled,
        mode: item.mode,
        match: item.match,
        action: item.action,
      };
    },
    removeMonitor(item) {
      if (item.source === "builtin") return;
      const confirmed = typeof window !== "undefined" ? window.confirm(`Delete monitor "${item.name}"?`) : true;
      if (!confirmed) return;
      this.setBusy(item.id, true);
      this.store
        .deleteMonitor(item.id)
        .then(() => this.load())
        .catch((err) => {
          this.error = (err && err.message) || "Failed to delete monitor";
        })
        .finally(() => {
          this.setBusy(item.id, false);
        });
    },
    openCreateDialog() {
      this.editingId = "";
      this.form = emptyForm();
      this.formError = "";
      this.dialogOpen = true;
    },
    openEditDialog(item) {
      const match = item.match || {};
      const action = item.action || {};
      this.editingId = item.id;
      this.form = {
        name: item.name || "",
        description: item.description || "",
        priority: item.priority || 100,
        severity: action.severity || "medium",
        tag: action.tag || "",
        mode: item.mode === "regex" ? "regex" : "rule",
        protocols: Array.isArray(match.protocols) ? [...match.protocols] : [],
        ports: Array.isArray(match.ports) ? match.ports.map(String) : [],
        payloadContains: Array.isArray(match.payload_contains) ? [...match.payload_contains] : [],
        minLength: match.min_length || null,
        maxLength: match.max_length || null,
        payloadRegex: Array.isArray(match.payload_regex) ? [...match.payload_regex] : [],
      };
      this.formError = "";
      this.dialogOpen = true;
    },
    buildMatchPayload() {
      if (this.form.mode === "regex") {
        const patterns = (this.form.payloadRegex || []).map((item) => String(item || "").trim()).filter(Boolean);
        return { payload_regex: patterns };
      }
      const ports = (this.form.ports || [])
        .map((item) => Number(item))
        .filter((value) => Number.isFinite(value) && value > 0);
      const contains = (this.form.payloadContains || []).map((item) => String(item || "").trim()).filter(Boolean);
      return {
        protocols: [...(this.form.protocols || [])],
        ports,
        payload_contains: contains,
        min_length: Number(this.form.minLength) || 0,
        max_length: Number(this.form.maxLength) || 0,
      };
    },
    submitForm() {
      this.formError = "";
      const name = String(this.form.name || "").trim();
      if (!name) {
        this.formError = "Name is required";
        return;
      }
      if (this.form.mode === "regex") {
        const patterns = (this.form.payloadRegex || []).map((item) => String(item || "").trim()).filter(Boolean);
        if (!patterns.length) {
          this.formError = "Add at least one regex pattern";
          return;
        }
        if (patterns.some((pattern) => !this.isValidRegex(pattern))) {
          this.formError = "One or more regex patterns are invalid";
          return;
        }
      }
      const payload = {
        id: this.editingId || undefined,
        name,
        description: String(this.form.description || "").trim(),
        priority: Number(this.form.priority) || 100,
        mode: this.form.mode,
        match: this.buildMatchPayload(),
        action: {
          severity: this.form.severity,
          tag: String(this.form.tag || "").trim(),
          label: name,
        },
      };
      this.formSubmitting = true;
      this.store
        .saveMonitor(payload)
        .then(() => {
          this.dialogOpen = false;
          return this.load();
        })
        .catch((err) => {
          this.formError = (err && err.message) || "Failed to save monitor";
        })
        .finally(() => {
          this.formSubmitting = false;
        });
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return Promise.allSettled([this.store.listMonitors(), this.store.getMonitorConfig()])
        .then(([monitorsRes, configRes]) => {
          if (monitorsRes.status === "fulfilled") {
            this.monitors = this.store.extractArray(monitorsRes.value);
          } else {
            this.monitors = [];
            this.error = (monitorsRes.reason && monitorsRes.reason.message) || "Failed to load monitors";
          }
          if (configRes.status === "fulfilled") {
            this.filterEnabled = Boolean(configRes.value && configRes.value.filter_enabled);
            this.configError = "";
          } else {
            this.configError = (configRes.reason && configRes.reason.message) || "Failed to load persistence filter state";
          }
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

.filter-card {
  border-radius: 16px;
}

.monitor-traffic-panels {
  border-radius: 16px;
  overflow: hidden;
}

.mode-toggle {
  width: 100%;
}

.match-summary {
  display: inline-block;
  max-width: 420px;
  overflow-wrap: anywhere;
  font-family: var(--font-mono);
  font-size: 0.85rem;
}
</style>
