<template>
  <div>
    <ViewHeader
      overline="Investigation"
      title="Host Investigator"
      description="Search an IP and get a compact, evidence-first view of transport, payloads, tags, and flows."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-row dense class="mb-3">
      <v-col cols="12" md="7">
        <v-text-field
          v-model.trim="queryIp"
          label="Investigate IP"
          name="investigate_ip"
          placeholder="127.0.0.1"
          prepend-inner-icon="mdi-magnify"
          clearable
          variant="outlined"
          density="comfortable"
          @keyup.enter="load"
        />
      </v-col>
      <v-col cols="12" md="3" class="d-flex align-center">
        <v-btn color="primary" variant="flat" class="mr-2" :disabled="loading || !queryIp" @click="load">
          Investigate
        </v-btn>
        <v-btn variant="outlined" :disabled="loading || !queryIp" @click="setTopSuggestion">
          Top host
        </v-btn>
      </v-col>
    </v-row>

    <div class="d-flex flex-wrap ga-2 mb-4">
      <v-chip
        v-for="item in suggestedHosts"
        :key="item.ip"
        size="small"
        variant="tonal"
        color="info"
        class="suggestion-chip"
        @click="queryIp = item.ip; load()"
      >
        {{ item.ip }} · {{ item.value }} open
      </v-chip>
    </div>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-6">
      {{ error }}
    </v-alert>

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

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="6">
        <DataPanel
          title="Host Profile"
          subtitle="Scope, caching, and host profile context."
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :show-refresh="false"
        >
          <div class="d-flex flex-wrap ga-2">
            <v-chip size="small" variant="tonal" color="primary">
              Scope: {{ hostScope }}
            </v-chip>
            <v-chip size="small" variant="tonal" color="info">
              Cached: {{ cachedLabel }}
            </v-chip>
            <v-chip size="small" variant="tonal" color="warning">
              Domains: {{ domainCount }}
            </v-chip>
            <v-chip size="small" variant="tonal" color="success">
              TTL hops: {{ ttlHopCount }}
            </v-chip>
          </div>
          <v-divider class="my-4" />
          <div class="text-subtitle-2 mb-2">Notes</div>
          <div class="text-body-2 text-medium-emphasis">
            {{ notesText }}
          </div>
        </DataPanel>
      </v-col>

      <v-col cols="12" xl="6">
        <DataPanel
          title="Application"
          subtitle="Quick application-layer fingerprint."
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :show-refresh="false"
        >
          <div class="d-flex flex-wrap ga-2">
            <v-chip size="small" variant="tonal" color="info">
              HTTP: {{ appHttpLabel }}
            </v-chip>
            <v-chip size="small" variant="tonal" color="warning">
              TLS: {{ appTlsLabel }}
            </v-chip>
            <v-chip size="small" variant="tonal" color="secondary">
              Fingerprint: {{ appFingerprintLabel }}
            </v-chip>
          </div>
        </DataPanel>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="7">
        <EntityTablePanel
          title="Transport Services"
          subtitle="Services inferred from the host IP."
          :rows="transportServices"
          :columns="serviceColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :search-enabled="true"
          search-label="Search services"
          search-placeholder="IP, port, proto, state, banner, or tags"
          :filter-definitions="serviceFilters"
          empty-text="No services for this host"
          :page-size="8"
          @refresh="load"
        >
          <template #cell-port="{ value }">
            <v-chip size="x-small" color="info" variant="tonal">
              {{ value }}
            </v-chip>
          </template>
          <template #cell-banner="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
          <template #cell-progress="{ value }">
            <ProgressCell :value="value" />
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="5">
        <EntityTablePanel
          title="Payload Evidence"
          subtitle="Captured response bodies and banner rows."
          :rows="payloadRows"
          :columns="payloadColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :search-enabled="true"
          search-label="Search payloads"
          search-placeholder="IP, port, proto, or response"
          :filter-definitions="payloadFilters"
          empty-text="No payload evidence for this host"
          :page-size="8"
          @refresh="load"
        >
          <template #cell-response_plain="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="7">
        <EntityTablePanel
          title="Flows"
          subtitle="Directed conversations tied to the selected host."
          :rows="flowRows"
          :columns="flowColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :search-enabled="true"
          search-label="Search flows"
          search-placeholder="Flow key, source, target, or banner"
          :filter-definitions="flowFilters"
          empty-text="No flows for this host"
          :page-size="8"
          @refresh="load"
        >
          <template #cell-banner_text="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="5">
        <EntityTablePanel
          title="Tags"
          subtitle="Rule hits and parsed tags."
          :rows="tagRows"
          :columns="tagColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :search-enabled="true"
          search-label="Search tags"
          search-placeholder="Key, value, proto, IP, or port"
          :filter-definitions="tagFilters"
          empty-text="No tags for this host"
          :page-size="8"
          @refresh="load"
        />
      </v-col>
    </v-row>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import ProgressCell from "../components/ui/ProgressCell.vue";
import { uniqueSorted } from "../utils/traffic";

export default {
  name: "InvestigateView",
  components: {
    ViewHeader,
    DataPanel,
    EntityTablePanel,
    ProgressCell,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      queryIp: "",
      analytics: {},
      intel: {},
      serviceColumns: [
        { key: "ip", label: "IP" },
        { key: "port", label: "Port" },
        { key: "proto", label: "Proto" },
        { key: "state", label: "State" },
        { key: "banner", label: "Banner" },
        { key: "progress", label: "Progress" },
      ],
      payloadColumns: [
        { key: "ip", label: "IP" },
        { key: "port", label: "Port" },
        { key: "proto", label: "Proto" },
        { key: "response_size", label: "Size" },
        { key: "response_plain", label: "Response" },
      ],
      flowColumns: [
        { key: "flow_key", label: "Flow" },
        { key: "proto", label: "Proto" },
        { key: "src_ip", label: "Source" },
        { key: "dst_ip", label: "Target" },
        { key: "src_port", label: "S Port" },
        { key: "dst_port", label: "D Port" },
        { key: "state", label: "State" },
        { key: "packet_count", label: "Packets" },
        { key: "byte_count", label: "Bytes" },
        { key: "banner_text", label: "Banner" },
      ],
      tagColumns: [
        { key: "key", label: "Key" },
        { key: "value", label: "Value" },
        { key: "proto", label: "Proto" },
        { key: "ip", label: "IP" },
        { key: "port", label: "Port" },
      ],
    };
  },
  computed: {
    summary() {
      return this.intel.summary || {};
    },
    host() {
      return this.intel.host || {};
    },
    hostProfile() {
      return this.intel.host_profile || {};
    },
    transport() {
      return this.host.transport && typeof this.host.transport === "object" ? this.host.transport : {};
    },
    application() {
      return this.hostProfile.application && typeof this.hostProfile.application === "object"
        ? this.hostProfile.application
        : {};
    },
    transportServices() {
      return Array.isArray(this.transport.services) ? this.transport.services : [];
    },
    serviceFilters() {
      return [
        {
          key: "proto",
          label: "Proto",
          value: "proto",
          options: uniqueSorted(this.transportServices.map((row) => row.proto)),
        },
        {
          key: "state",
          label: "State",
          value: "state",
          options: uniqueSorted(this.transportServices.map((row) => row.state)),
        },
      ];
    },
    payloadRows() {
      return Array.isArray(this.transport.banners) ? this.transport.banners : [];
    },
    payloadFilters() {
      return [
        {
          key: "proto",
          label: "Proto",
          value: "proto",
          options: uniqueSorted(this.payloadRows.map((row) => row.proto)),
        },
      ];
    },
    flowRows() {
      return Array.isArray(this.transport.flows) ? this.transport.flows : [];
    },
    flowFilters() {
      return [
        {
          key: "proto",
          label: "Proto",
          value: "proto",
          options: uniqueSorted(this.flowRows.map((row) => row.proto)),
        },
        {
          key: "state",
          label: "State",
          value: "state",
          options: uniqueSorted(this.flowRows.map((row) => row.state)),
        },
      ];
    },
    tagRows() {
      return Array.isArray(this.transport.tags) ? this.transport.tags : [];
    },
    tagFilters() {
      return [
        {
          key: "proto",
          label: "Proto",
          value: "proto",
          options: uniqueSorted(this.tagRows.map((row) => row.proto)),
        },
      ];
    },
    metricCards() {
      return [
        {
          key: "packets",
          label: "Packets",
          value: Number(this.summary.packets || 0),
          caption: "Packets tied to this host",
          icon: "mdi-ethernet",
          colorClass: "text-success",
        },
        {
          key: "flows",
          label: "Flows",
          value: Number(this.summary.flows || 0),
          caption: "Correlated conversations",
          icon: "mdi-source-branch",
          colorClass: "text-info",
        },
        {
          key: "payloads",
          label: "Payloads",
          value: Number(this.summary.payloads || 0),
          caption: "Evidence rows and banners",
          icon: "mdi-message-text",
          colorClass: "text-warning",
        },
        {
          key: "tags",
          label: "Tags",
          value: Number(this.summary.tags || 0),
          caption: "Rule hits and parsed tags",
          icon: "mdi-tag-multiple",
          colorClass: "text-primary",
        },
      ];
    },
    hostScope() {
      return String((this.hostProfile.target && this.hostProfile.target.scope) || "unknown");
    },
    cachedLabel() {
      return this.intel.cached ? "yes" : "no";
    },
    domainCount() {
      const domains = this.intel.domains && Array.isArray(this.intel.domains.domains) ? this.intel.domains.domains : [];
      return domains.length;
    },
    ttlHopCount() {
      const hops = this.intel.ttl_path && Array.isArray(this.intel.ttl_path.hops) ? this.intel.ttl_path.hops : [];
      return hops.length;
    },
    notesText() {
      const notes = Array.isArray(this.hostProfile.notes) ? this.hostProfile.notes : [];
      if (!notes.length) return "No operator notes captured for this host.";
      return notes.join(" | ");
    },
    appHttpLabel() {
      const http = this.application.http || {};
      return http.banner ? "banner set" : "empty";
    },
    appTlsLabel() {
      const tls = this.application.tls || {};
      return Object.keys(tls.fingerprint || {}).length ? "fingerprint set" : "empty";
    },
    appFingerprintLabel() {
      const fingerprint = this.application.fingerprint || {};
      return Object.keys(fingerprint).length ? "present" : "empty";
    },
    suggestedHosts() {
      const rows = Array.isArray(this.analytics.top_ips_by_open_ports) ? this.analytics.top_ips_by_open_ports : [];
      return rows.slice(0, 8);
    },
    apiBase() {
      return this.store.state.apiBase;
    },
  },
  watch: {
    apiBase() {
      this.load();
    },
    $route: {
      immediate: true,
      handler(route) {
        const ip = String((route && route.query && route.query.ip) || "").trim();
        if (ip && ip !== this.queryIp) {
          this.queryIp = ip;
          this.load();
        }
      },
    },
  },
  mounted() {
    if (!this.queryIp) {
      this.loadSeed();
    }
  },
  methods: {
    loadSeed() {
      return this.store.fetchJsonPromise("/api/charts/analytics").then((payload) => {
        this.analytics = payload || {};
        const top = Array.isArray(this.analytics.top_ips_by_open_ports) ? this.analytics.top_ips_by_open_ports[0] : null;
        if (top && top.ip) {
          this.queryIp = top.ip;
          return this.load();
        }
        return this.load();
      });
    },
    setTopSuggestion() {
      const top = this.suggestedHosts[0];
      if (!top || !top.ip) return;
      this.queryIp = top.ip;
      this.load();
    },
    load() {
      const ip = String(this.queryIp || "").trim();
      if (!ip) {
        this.error = "Enter an IP to investigate.";
        this.intel = {};
        return Promise.resolve();
      }
      this.loading = true;
      this.error = "";
      return Promise.allSettled([
        this.store.fetchJsonPromise("/api/charts/analytics"),
        this.store.fetchJsonPromise(`/api/ip/intel/?ip=${encodeURIComponent(ip)}`),
      ])
        .then(([analyticsRes, intelRes]) => {
          if (analyticsRes.status === "fulfilled") {
            this.analytics = analyticsRes.value || {};
          }
          if (intelRes.status === "fulfilled") {
            this.intel = intelRes.value || {};
          } else {
            this.intel = {};
            this.error = (intelRes.reason && intelRes.reason.message) || `Failed to investigate ${ip}`;
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

.suggestion-chip {
  cursor: pointer;
}

.summary-cell {
  display: inline-block;
  max-width: 220px;
  overflow-wrap: anywhere;
}
</style>
