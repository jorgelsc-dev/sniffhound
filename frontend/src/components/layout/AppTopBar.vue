<template>
  <v-app-bar color="transparent" flat height="74" class="top-bar">
    <v-container class="d-flex align-center app-topbar">
      <v-btn
        icon="mdi-menu"
        variant="text"
        class="d-md-none menu-trigger"
        aria-label="Open navigation menu"
        @click="$emit('open-drawer')"
      />
      <div class="brand-lockup">
        <v-avatar size="44" class="mr-3">
          <v-img :src="brandIconSrc" alt="SniffHound" />
        </v-avatar>
        <div class="brand-copy">
          <div class="text-subtitle-1 font-weight-bold">SniffHound</div>
          <div class="text-caption text-medium-emphasis">
            Telemetry capture &amp; honeypot control
          </div>
        </div>
      </div>

      <v-spacer />

      <v-tabs
        class="d-none d-md-flex top-tabs"
        color="primary"
        density="compact"
        align-with-title
      >
        <v-tab
          v-for="item in navItems"
          :key="item.to"
          :to="item.to"
          :exact="item.to === '/'"
        >
          {{ item.label }}
        </v-tab>
      </v-tabs>

      <v-spacer />

      <div class="status-rail">
        <v-chip
          :color="authStateColor"
          variant="tonal"
          size="small"
          prepend-icon="mdi-shield-key-outline"
          class="auth-chip"
          @click="$emit('open-auth')"
        >
          {{ authStateLabel }}
        </v-chip>
        <v-chip
          :color="wsStateColor"
          variant="tonal"
          size="small"
          prepend-icon="mdi-access-point"
        >
          {{ wsStateLabel }}
        </v-chip>
        <v-chip
          :color="runtimeStateColor"
          variant="tonal"
          size="small"
          prepend-icon="mdi-toggle-switch"
        >
          {{ runtimeStateLabel }}
        </v-chip>
      </div>
    </v-container>
  </v-app-bar>
</template>

<script>
import store from "../../state/appStore";
import { appBaseUrl } from "../../utils/runtimeEnv";

export default {
  name: "AppTopBar",
  props: {
    navItems: {
      type: Array,
      default: () => [],
    },
    authRequired: {
      type: Boolean,
      default: false,
    },
    authStatus: {
      type: String,
      default: "unknown",
    },
    wsStatus: {
      type: String,
      default: "offline",
    },
  },
  emits: ["open-auth", "open-drawer"],
  computed: {
    authStateLabel() {
      if (!this.authRequired) return "Auth Open";
      if (this.authStatus === "authenticated") return "Auth Ready";
      if (this.authStatus === "required") return "Auth Required";
      return "Auth Check";
    },
    authStateColor() {
      if (!this.authRequired) return "info";
      if (this.authStatus === "authenticated") return "success";
      if (this.authStatus === "required") return "warning";
      return "secondary";
    },
    runtimeStateLabel() {
      const runtime = store.state.runtime || {};
      const mode = String(runtime.mode || store.state.runtimeMode || "").trim().toLowerCase();
      if (mode === "honeypot") return "Mode: Honeypot";
      return "Mode: Sniffer";
    },
    runtimeStateColor() {
      const runtime = store.state.runtime || {};
      const mode = String(runtime.mode || store.state.runtimeMode || "").trim().toLowerCase();
      if (mode === "honeypot") return "warning";
      return "info";
    },
    wsStateLabel() {
      const value = String(this.wsStatus || "").trim().toLowerCase();
      if (value === "online") return "WS Online";
      if (value === "connecting") return "WS Connecting";
      if (value === "locked") return "WS Locked";
      if (value === "error") return "WS Error";
      return "WS Offline";
    },
    wsStateColor() {
      const value = String(this.wsStatus || "").trim().toLowerCase();
      if (value === "online") return "success";
      if (value === "connecting") return "info";
      if (value === "locked") return "secondary";
      if (value === "error") return "error";
      return "warning";
    },
    brandIconSrc() {
      return `${appBaseUrl()}brand-icon.png`;
    },
  },
};
</script>

<style scoped>
.top-bar {
  border-bottom: 1px solid rgba(97, 176, 221, 0.2);
  backdrop-filter: blur(16px);
  background: linear-gradient(
    180deg,
    rgba(10, 16, 27, 0.93) 0%,
    rgba(10, 16, 27, 0.72) 72%,
    rgba(10, 16, 27, 0.2) 100%
  );
}

.app-topbar {
  max-width: 1560px;
  width: 100%;
}

.brand-lockup {
  display: flex;
  align-items: center;
  min-width: 0;
}

.brand-copy {
  min-width: 0;
}

.top-tabs :deep(.v-tab) {
  min-width: 72px;
  font-weight: 600;
  letter-spacing: 0.04em;
}

.status-rail {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  min-width: 0;
  flex-wrap: wrap;
}

.auth-chip {
  cursor: pointer;
}

@media (max-width: 959px) {
  .top-bar {
    height: auto !important;
  }

  .app-topbar {
    flex-wrap: wrap;
    row-gap: 10px;
    padding-top: 10px;
    padding-bottom: 10px;
  }

  .top-tabs {
    display: none !important;
  }

  .brand-lockup {
    flex: 1 1 auto;
    min-width: 0;
  }

  .brand-copy .text-subtitle-1 {
    font-size: 0.98rem !important;
  }

  .brand-copy .text-caption {
    display: block;
    max-width: 180px;
    line-height: 1.35;
    white-space: normal;
  }

  .status-rail {
    width: 100%;
    justify-content: flex-start;
    flex-wrap: nowrap;
    overflow-x: auto;
    padding-bottom: 2px;
  }

  .status-rail::-webkit-scrollbar {
    height: 4px;
  }

  .status-rail :deep(.v-chip) {
    flex: 0 0 auto;
  }
}
</style>
