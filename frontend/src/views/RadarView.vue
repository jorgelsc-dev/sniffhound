<template>
  <div>
    <ViewHeader
      overline="Recon"
      title="Traffic Radar"
      description="A fast map of what is hot right now: protocol mix, risky ports, top hosts, and the live topology."
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

    <div class="mt-6">
      <MapPanel
        panel-title="Topology Radar"
        panel-subtitle="See host placement and point density at a glance."
        :show-refresh="true"
        :show-panel-header="false"
        :show-intro="true"
        :show-projection-switch="true"
        :immersive="true"
      />
    </div>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="7">
        <DataPanel
          title="Timeline"
          subtitle="Packet activity over time."
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :show-refresh="false"
        >
          <div class="timeline-chip-grid">
            <v-chip
              v-for="item in timelineSeries"
              :key="item.label"
              size="small"
              variant="tonal"
              color="info"
            >
              {{ item.label }}: {{ item.value }}
            </v-chip>
            <span v-if="!timelineSeries.length" class="text-body-2 text-medium-emphasis">
              No timeline points yet.
            </span>
          </div>
        </DataPanel>
      </v-col>

      <v-col cols="12" xl="5">
        <DataPanel
          title="Signals"
          subtitle="Protocol mix, service signatures, and tag patterns."
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :show-refresh="false"
        >
          <div class="d-flex flex-wrap ga-2 mb-3">
            <v-chip
              v-for="item in portsByProto"
              :key="item.label"
              size="small"
              variant="tonal"
              color="info"
            >
              {{ item.label }} · {{ item.value }}
            </v-chip>
          </div>
          <div class="d-flex flex-wrap ga-2">
            <v-chip
              v-for="item in topSignatures"
              :key="item.label"
              size="small"
              variant="outlined"
              color="warning"
            >
              {{ item.label }}
            </v-chip>
          </div>
        </DataPanel>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="6">
        <EntityTablePanel
          title="Risk Ports"
          subtitle="Highest hit ports seen in the current slice."
          :rows="riskPorts"
          :columns="riskPortColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :search-enabled="true"
          search-label="Search ports"
          search-placeholder="Port, hit count, or label"
          empty-text="No risk ports yet"
          :page-size="8"
          @refresh="load"
        >
          <template #cell-port="{ value }">
            <v-chip size="x-small" color="warning" variant="tonal">
              {{ value }}
            </v-chip>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="6">
        <EntityTablePanel
          title="Top Hosts"
          subtitle="Hosts with the most open ports."
          :rows="topHosts"
          :columns="hostColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :search-enabled="true"
          search-label="Search hosts"
          search-placeholder="IP or open ports"
          empty-text="No host activity yet"
          :page-size="8"
          @refresh="load"
        >
          <template #cell-ip="{ item, value }">
            <router-link class="host-link" :to="{ path: '/investigate', query: { ip: value } }">
              {{ item.ip }}
            </router-link>
          </template>
          <template #cell-open_ports="{ value }">
            <v-chip size="x-small" color="info" variant="tonal">
              {{ value }}
            </v-chip>
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
import MapPanel from "../components/MapPanel.vue";

export default {
  name: "RadarView",
  components: {
    ViewHeader,
    DataPanel,
    EntityTablePanel,
    MapPanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      analytics: {},
      mapSnapshot: {},
      riskPortColumns: [
        { key: "port", label: "Port" },
        { key: "value", label: "Hits" },
      ],
      hostColumns: [
        { key: "ip", label: "IP" },
        { key: "value", label: "Open Ports" },
      ],
    };
  },
  computed: {
    metricCards() {
      const summary = this.analytics.summary || {};
      const mapSummary = this.mapSnapshot.summary || {};
      return [
        {
          key: "packets",
          label: "Packets",
          value: Number(summary.ports || 0),
          caption: "Traffic rows seen in analytics",
          icon: "mdi-ethernet",
          colorClass: "text-success",
        },
        {
          key: "hosts",
          label: "Hosts",
          value: Number(mapSummary.total_hosts || summary.unique_hosts || 0),
          caption: "Distinct hosts in the map snapshot",
          icon: "mdi-lan-connect",
          colorClass: "text-info",
        },
        {
          key: "open",
          label: "Open Ports",
          value: Number(summary.open_ports || 0),
          caption: "Ports with active responses",
          icon: "mdi-radar",
          colorClass: "text-warning",
        },
        {
          key: "banners",
          label: "Responses",
          value: Number(summary.banners || 0),
          caption: "Decoded payload evidence",
          icon: "mdi-message-text",
          colorClass: "text-primary",
        },
      ];
    },
    timelineSeries() {
      return Array.isArray(this.analytics.timeline) ? this.analytics.timeline.slice(-14) : [];
    },
    topSignatures() {
      return Array.isArray(this.analytics.top_service_signatures) ? this.analytics.top_service_signatures.slice(0, 12) : [];
    },
    portsByProto() {
      return Array.isArray(this.analytics.ports_by_proto) ? this.analytics.ports_by_proto.slice(0, 8) : [];
    },
    riskPorts() {
      return Array.isArray(this.analytics.risk_ports) ? this.analytics.risk_ports.slice(0, 12) : [];
    },
    topHosts() {
      return Array.isArray(this.analytics.top_ips_by_open_ports) ? this.analytics.top_ips_by_open_ports.slice(0, 12) : [];
    },
  },
  watch: {
    apiBase() {
      this.load();
    },
  },
  mounted() {
    this.load();
  },
  methods: {
    load() {
      this.loading = true;
      this.error = "";
      return Promise.allSettled([
        this.store.fetchJsonPromise("/api/charts/analytics"),
        this.store.fetchJsonPromise("/api/map/scan?limit=500"),
      ])
        .then(([analyticsRes, mapRes]) => {
          if (analyticsRes.status === "fulfilled") {
            this.analytics = analyticsRes.value || {};
          } else {
            this.analytics = {};
            this.error = (analyticsRes.reason && analyticsRes.reason.message) || "Failed to load analytics";
          }
          if (mapRes.status === "fulfilled") {
            this.mapSnapshot = (mapRes.value && mapRes.value.data) || {};
          } else if (!this.error) {
            this.mapSnapshot = {};
            this.error = (mapRes.reason && mapRes.reason.message) || "Failed to load map snapshot";
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

.timeline-chip-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.host-link {
  color: rgba(108, 186, 228, 0.98);
  text-decoration: none;
}

.host-link:hover {
  text-decoration: underline;
}
</style>
