<template>
  <v-sheet class="hero-banner" rounded="xl">
    <v-row align="center" class="pa-6 pa-md-8">
      <v-col cols="12">
        <div class="text-overline text-primary">Network telemetry</div>
        <div class="text-h4 text-md-h3 font-weight-bold">SniffHound Control Room</div>
        <div class="text-body-1 text-medium-emphasis mt-2">
          Start and configure the sniffer or the honeypot from their own dedicated views, then
          drill into passive capture, inbound honeypot hits, and detection monitors from here.
        </div>
        <div class="d-flex flex-wrap ga-3 mt-4">
          <v-btn color="primary" variant="flat" to="/sniffer">Sniffer</v-btn>
          <v-btn color="warning" variant="outlined" to="/honeypot">Honeypot</v-btn>
          <v-btn color="info" variant="outlined" to="/monitors">Monitors</v-btn>
        </div>
        <v-alert
          class="usage-notice mt-5"
          type="warning"
          variant="tonal"
          density="comfortable"
          icon="mdi-shield-check-outline"
        >
          Authorized use only. Run SniffHound exclusively on systems, networks and IP ranges you
          own or administer, and only activate honeypot mode where you are allowed to bind the
          selected ports.
        </v-alert>
      </v-col>
    </v-row>
  </v-sheet>
</template>

<script>
export default {
  name: "AppHero",
};
</script>

<style scoped>
.hero-banner {
  position: relative;
  overflow: hidden;
  background:
    radial-gradient(110% 140% at -8% -24%, rgba(var(--brand-cyan-rgb), 0.2), transparent 58%),
    radial-gradient(90% 110% at 110% -30%, rgba(var(--brand-violet-rgb), 0.18), transparent 63%),
    linear-gradient(122deg, rgba(9, 14, 23, 0.98), rgba(7, 12, 20, 0.98));
  border: 1px solid rgba(var(--brand-sky-rgb), 0.22);
  box-shadow: 0 28px 56px rgba(2, 7, 14, 0.44), inset 0 0 0 1px rgba(255, 255, 255, 0.03);
}

.hero-banner::before {
  content: "";
  position: absolute;
  left: -8%;
  right: -8%;
  bottom: -80px;
  height: 220px;
  background: radial-gradient(
    60% 100% at 50% 100%,
    rgba(var(--brand-violet-rgb), 0.2),
    rgba(var(--brand-violet-rgb), 0)
  );
  pointer-events: none;
}

.usage-notice {
  border: 1px solid rgba(var(--brand-violet-rgb), 0.22);
  background:
    linear-gradient(180deg, rgba(23, 18, 46, 0.82), rgba(12, 15, 28, 0.64)) !important;
}

.hero-banner :deep(.v-btn) {
  letter-spacing: 0.04em;
}
</style>
