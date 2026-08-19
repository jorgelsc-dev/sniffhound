<template>
  <div class="pa-6">
    <h2 class="mb-4">Include/Exclude Filter Test Harness (temporary)</h2>
    <EntityTablePanel
      title="Test packets"
      subtitle="Hover a cell to see +/- buttons"
      :rows="rows"
      :columns="columns"
      search-enabled
      search-label="Search"
    >
      <template #cell-proto="{ value }">
        <v-chip size="x-small" color="primary" variant="tonal">{{ value }}</v-chip>
      </template>
    </EntityTablePanel>
  </div>
</template>

<script>
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";

export default {
  name: "FilterTestView",
  components: { EntityTablePanel },
  data() {
    return {
      columns: [
        { key: "proto", label: "Proto" },
        { key: "src_ip", label: "Source" },
        { key: "dst_ip", label: "Target" },
        { key: "summary", label: "Summary" },
      ],
      rows: [
        { id: 1, proto: "tcp", src_ip: "192.168.1.10", dst_ip: "8.8.8.8", summary: "TCP handshake" },
        { id: 2, proto: "udp", src_ip: "192.168.1.11", dst_ip: "1.1.1.1", summary: "DNS query" },
        { id: 3, proto: "tcp", src_ip: "192.168.1.10", dst_ip: "10.0.0.5", summary: "HTTP GET /" },
        { id: 4, proto: "icmp", src_ip: "192.168.1.12", dst_ip: "192.168.1.1", summary: "Echo request" },
        { id: 5, proto: "udp", src_ip: "192.168.1.13", dst_ip: "8.8.4.4", summary: "DNS query 2" },
      ],
    };
  },
};
</script>
