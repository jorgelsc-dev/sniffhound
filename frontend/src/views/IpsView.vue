<template>
  <div>
    <ViewHeader
      overline="Detection"
      title="IPs"
      description="Distinct source/destination IPs seen in stored (detected) traffic."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">
      {{ error }}
    </v-alert>

    <v-row dense>
      <v-col v-for="chart in chartPanels" :key="chart.key" cols="12" md="6">
        <ChartCard
          :title="chart.title"
          :subtitle="chart.subtitle"
          :series="chart.series"
          :fill="chart.fill"
          :color="chart.color"
        />
      </v-col>
    </v-row>

    <EntityTablePanel
      title="IPs"
      subtitle="One row per distinct IP address seen in stored traffic."
      class="mt-6"
      v-model:live-enabled="liveRefreshEnabled"
      :live-refresh="true"
      :rows="ips"
      :columns="columns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      search-enabled
      search-label="Search IPs"
      search-placeholder="IP address..."
      :page-size="25"
      empty-text="No IPs observed yet"
      @refresh="load"
    >
      <template #cell-ip="{ value }">
        <router-link v-if="value" class="mono ip-link" :to="{ path: '/investigate', query: { ip: value } }">
          {{ value }}
        </router-link>
        <span v-else>-</span>
      </template>
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
import ChartCard from "../components/ui/ChartCard.vue";
import { formatTimestamp, groupSumSeries, topSeriesByValue } from "../utils/traffic";

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

export default {
  name: "IpsView",
  components: {
    ViewHeader,
    EntityTablePanel,
    ChartCard,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      ips: [],
      liveRefreshEnabled: true,
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
      columns: [
        { key: "ip", label: "IP" },
        { key: "private", label: "Scope", sortable: false },
        { key: "hit_count", label: "Hits" },
        { key: "first_seen", label: "First seen" },
        { key: "last_seen", label: "Last seen" },
      ],
    };
  },
  computed: {
    chartPanels() {
      return [
        {
          key: "top",
          title: "Top IPs by hits",
          subtitle: "Highest-traffic addresses in this slice.",
          color: "info",
          fill: "linear-gradient(90deg, rgba(52, 230, 255, 0.94), rgba(74, 136, 255, 0.85))",
          series: topSeriesByValue(this.ips, (item) => item.ip, (item) => item.hit_count, 8),
        },
        {
          key: "scope",
          title: "Public vs private",
          subtitle: "Total hits grouped by address scope.",
          color: "warning",
          fill: "linear-gradient(90deg, rgba(255, 159, 67, 0.92), rgba(243, 177, 75, 0.78))",
          series: groupSumSeries(this.ips, (item) => (item.private ? "Private" : "Public"), (item) => item.hit_count),
        },
      ];
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
    formatTimestamp,
    handleWsRefresh(event) {
      if (!this.liveRefreshEnabled) return;
      const eventType = String((event && event.type) || "").trim().toLowerCase();
      if (!REFRESH_EVENT_TYPES.has(eventType)) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.load({ silent: true }).catch(() => {
          // keep current data on transient refresh errors
        });
      }, 10000);
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return this.store
        .listIpCatalog({ limit: 500 })
        .then((payload) => {
          this.ips = this.store.extractArray(payload);
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.ips = [];
          this.error = (err && err.message) || "Failed to load IPs";
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.mono {
  font-family: var(--font-mono);
}

.ip-link {
  color: rgba(108, 186, 228, 0.98);
  text-decoration: none;
}

.ip-link:hover {
  text-decoration: underline;
}
</style>
