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
        <div class="brand-avatar mr-3">
          <BrandMark :size="44" />
        </div>
        <div class="brand-copy">
          <div class="text-subtitle-1 font-weight-bold">SniffHound</div>
          <div class="text-caption text-medium-emphasis">
            Telemetry capture &amp; service listeners
          </div>
        </div>
      </div>

      <v-spacer />

      <v-tabs
        class="d-none d-md-flex top-tabs"
        color="primary"
        density="compact"
        center-active
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
        <div class="runtime-actions" aria-label="Runtime controls">
          <v-btn
            :icon="snifferActionIcon"
            :color="snifferActionColor"
            variant="tonal"
            size="small"
            density="comfortable"
            class="runtime-action-btn"
            :loading="runtimeSubmitting === 'sniffer'"
            :disabled="runtimeControlsDisabled || runtimeSubmitting === 'services'"
            :aria-label="snifferActionLabel"
            @click="toggleRuntime('sniffer')"
          >
            <v-icon :icon="snifferActionIcon" />
            <v-tooltip activator="parent" location="bottom">{{ snifferActionLabel }}</v-tooltip>
          </v-btn>
          <v-btn
            :icon="servicesActionIcon"
            :color="servicesActionColor"
            variant="tonal"
            size="small"
            density="comfortable"
            class="runtime-action-btn"
            :loading="runtimeSubmitting === 'services'"
            :disabled="runtimeControlsDisabled || runtimeSubmitting === 'sniffer'"
            :aria-label="servicesActionLabel"
            @click="toggleRuntime('services')"
          >
            <v-icon :icon="servicesActionIcon" />
            <v-tooltip activator="parent" location="bottom">{{ servicesActionLabel }}</v-tooltip>
          </v-btn>
        </div>
        <NotificationBell />
        <v-btn
          icon="mdi-cog-outline"
          variant="text"
          size="small"
          density="comfortable"
          class="settings-btn"
          to="/settings"
          aria-label="Settings"
        >
          <v-icon icon="mdi-cog-outline" />
          <v-tooltip activator="parent" location="bottom">Settings</v-tooltip>
        </v-btn>
        <v-btn
          icon="mdi-power"
          color="error"
          variant="tonal"
          size="small"
          density="comfortable"
          class="shutdown-btn"
          :loading="shutdownPending"
          :disabled="shutdownPending"
          :aria-label="shutdownPending ? 'Stopping...' : 'Stop App'"
          @click="$emit('shutdown-app')"
        >
          <v-icon icon="mdi-power" />
          <v-tooltip activator="parent" location="bottom">
            {{ shutdownPending ? "Stopping..." : "Stop App" }}
          </v-tooltip>
        </v-btn>
        <v-chip
          :color="authStateColor"
          variant="tonal"
          size="small"
          class="auth-chip status-chip"
          :aria-label="authStateLabel"
          @click="$emit('open-auth')"
        >
          <v-icon :icon="authStateIcon" />
          <v-tooltip activator="parent" location="bottom">{{ authStateLabel }}</v-tooltip>
        </v-chip>
        <v-chip
          :color="wsStateColor"
          variant="tonal"
          size="small"
          class="status-chip"
          :aria-label="wsStateLabel"
        >
          <v-icon :icon="wsStateIcon" />
          <v-tooltip activator="parent" location="bottom">{{ wsStateLabel }}</v-tooltip>
        </v-chip>
        <v-chip
          :color="runtimeStateColor"
          variant="tonal"
          size="small"
          class="status-chip"
          :aria-label="runtimeStateLabel"
        >
          <v-icon :icon="runtimeStateIcon" />
          <v-tooltip activator="parent" location="bottom">{{ runtimeStateLabel }}</v-tooltip>
        </v-chip>
      </div>
    </v-container>
  </v-app-bar>
</template>

<script>
import BrandMark from "../brand/BrandMark.vue";
import NotificationBell from "./NotificationBell.vue";
import store from "../../state/appStore";

export default {
  name: "AppTopBar",
  components: {
    BrandMark,
    NotificationBell,
  },
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
    shutdownPending: {
      type: Boolean,
      default: false,
    },
  },
  emits: ["open-auth", "open-drawer", "shutdown-app"],
  data() {
    return {
      runtimeSubmitting: "",
    };
  },
  computed: {
    runtime() {
      const runtime = store.state.runtime || {};
      return runtime && typeof runtime === "object" ? runtime : {};
    },
    snifferRuntime() {
      return this.runtime.sniffer && typeof this.runtime.sniffer === "object" ? this.runtime.sniffer : {};
    },
    servicesRuntime() {
      return this.runtime.honeypot && typeof this.runtime.honeypot === "object" ? this.runtime.honeypot : {};
    },
    runtimeControlsDisabled() {
      return Boolean(this.authRequired && this.authStatus !== "authenticated");
    },
    snifferRunning() {
      return Boolean(this.snifferRuntime.running);
    },
    servicesRunning() {
      return Boolean(this.servicesRuntime.running);
    },
    snifferActionLabel() {
      return this.snifferRunning ? "Stop Sniffer" : "Start Sniffer";
    },
    snifferActionIcon() {
      return this.snifferRunning ? "mdi-stop" : "mdi-play";
    },
    snifferActionColor() {
      return this.snifferRunning ? "warning" : "primary";
    },
    servicesActionLabel() {
      return this.servicesRunning ? "Stop Services" : "Start Services";
    },
    servicesActionIcon() {
      return this.servicesRunning ? "mdi-stop" : "mdi-play";
    },
    servicesActionColor() {
      return this.servicesRunning ? "warning" : "success";
    },
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
    authStateIcon() {
      if (!this.authRequired) return "mdi-shield-outline";
      if (this.authStatus === "authenticated") return "mdi-shield-check-outline";
      if (this.authStatus === "required") return "mdi-shield-alert-outline";
      return "mdi-shield-key-outline";
    },
    runtimeStateLabel() {
      const runtime = store.state.runtime || {};
      const mode = String(runtime.mode || store.state.runtimeMode || "").trim().toLowerCase();
      if (mode === "honeypot") return "Mode: Services";
      return "Mode: Sniffer";
    },
    runtimeStateColor() {
      const runtime = store.state.runtime || {};
      const mode = String(runtime.mode || store.state.runtimeMode || "").trim().toLowerCase();
      if (mode === "honeypot") return "warning";
      return "info";
    },
    runtimeStateIcon() {
      const runtime = store.state.runtime || {};
      const mode = String(runtime.mode || store.state.runtimeMode || "").trim().toLowerCase();
      if (mode === "honeypot") return "mdi-server-security";
      return "mdi-database-outline";
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
    wsStateIcon() {
      const value = String(this.wsStatus || "").trim().toLowerCase();
      if (value === "online") return "mdi-access-point";
      if (value === "connecting") return "mdi-progress-clock";
      if (value === "locked") return "mdi-lock-outline";
      if (value === "error") return "mdi-access-point-off";
      return "mdi-access-point-off";
    },
  },
  methods: {
    toggleRuntime(kind) {
      if (this.runtimeSubmitting || this.runtimeControlsDisabled) return;
      const isServices = kind === "services";
      const mode = isServices ? "honeypot" : "sniffer";
      const action = (isServices ? this.servicesRunning : this.snifferRunning) ? "stop" : "start";
      this.runtimeSubmitting = kind;
      store
        .controlRuntimeMode(mode, action)
        .catch((error) => {
          if (typeof window !== "undefined" && error && error.message) {
            window.alert(error.message);
          }
        })
        .finally(() => {
          this.runtimeSubmitting = "";
        });
    },
  },
};
</script>

<style scoped>
.top-bar {
  position: relative;
  overflow: hidden;
  border-bottom: 1px solid rgba(var(--brand-sky-rgb), 0.18);
  backdrop-filter: blur(18px) saturate(130%);
  background:
    radial-gradient(circle at 18% 0%, rgba(var(--brand-cyan-rgb), 0.14), transparent 34%),
    radial-gradient(circle at 82% 0%, rgba(var(--brand-violet-rgb), 0.16), transparent 40%),
    linear-gradient(180deg, rgba(6, 11, 18, 0.94) 0%, rgba(9, 17, 29, 0.78) 72%, rgba(9, 17, 29, 0.18) 100%);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
}

.top-bar::after {
  content: "";
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(
    90deg,
    rgba(var(--brand-cyan-rgb), 0),
    rgba(var(--brand-cyan-rgb), 0.95),
    rgba(var(--brand-blue-rgb), 0.94),
    rgba(var(--brand-violet-rgb), 0.96),
    rgba(var(--brand-cyan-rgb), 0)
  );
  pointer-events: none;
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

.brand-avatar {
  width: 44px;
  height: 44px;
  flex: 0 0 44px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 14px;
  border: 1px solid rgba(var(--brand-cyan-rgb), 0.22);
  background:
    radial-gradient(circle at 24% 22%, rgba(var(--brand-cyan-rgb), 0.14), transparent 44%),
    linear-gradient(145deg, rgba(10, 16, 27, 0.92), rgba(7, 12, 21, 0.86));
  box-shadow:
    0 0 0 1px rgba(var(--brand-violet-rgb), 0.12),
    0 0 18px rgba(var(--brand-cyan-rgb), 0.16);
  overflow: hidden;
}

.brand-copy {
  min-width: 0;
}

.brand-copy .text-subtitle-1 {
  letter-spacing: 0.04em;
}

.brand-copy .text-caption {
  text-transform: uppercase;
  letter-spacing: 0.12em;
  font-size: 0.68rem !important;
}

.top-tabs {
  -webkit-mask-image: none;
  mask-image: none;
}

/* Only fade an edge while that side still has tabs scrolled out of view
   (Vuetify marks the scroll button --disabled once there's nothing left to reveal). */
.top-tabs:has(.v-slide-group__prev:not(.v-slide-group__prev--disabled)) {
  -webkit-mask-image: linear-gradient(to right, transparent 0, transparent 76px, black 120px);
  mask-image: linear-gradient(to right, transparent 0, transparent 76px, black 120px);
}

.top-tabs:has(.v-slide-group__next:not(.v-slide-group__next--disabled)) {
  -webkit-mask-image: linear-gradient(to left, transparent 0, transparent 76px, black 120px);
  mask-image: linear-gradient(to left, transparent 0, transparent 76px, black 120px);
}

.top-tabs:has(.v-slide-group__prev:not(.v-slide-group__prev--disabled)):has(.v-slide-group__next:not(.v-slide-group__next--disabled)) {
  -webkit-mask-image: linear-gradient(
    to right,
    transparent 0,
    transparent 76px,
    black 120px,
    black calc(100% - 120px),
    transparent calc(100% - 76px),
    transparent 100%
  );
  mask-image: linear-gradient(
    to right,
    transparent 0,
    transparent 76px,
    black 120px,
    black calc(100% - 120px),
    transparent calc(100% - 76px),
    transparent 100%
  );
}

.top-tabs :deep(.v-tab) {
  min-width: 72px;
  font-weight: 650;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.top-tabs :deep(.v-tab--selected) {
  color: rgba(var(--brand-cyan-rgb), 0.98);
  text-shadow: 0 0 14px rgba(var(--brand-cyan-rgb), 0.18);
}

.status-rail {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 10px;
  min-width: 0;
  flex-wrap: wrap;
}

.runtime-actions {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.16);
  border-radius: 999px;
  background: rgba(5, 10, 18, 0.36);
}

.runtime-action-btn {
  flex: 0 0 auto;
}

.auth-chip {
  cursor: pointer;
}

.shutdown-btn {
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

@media (max-width: 959px) {
  .top-bar {
    height: auto !important;
  }

  .top-bar :deep(.v-toolbar__content) {
    height: auto !important;
    min-height: 74px;
    overflow: visible;
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
