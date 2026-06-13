<template>
  <div v-if="hasControls" class="live-refresh-control">
    <div v-if="showLive" class="live-refresh-control__toggle-shell">
      <span class="live-refresh-control__spark" aria-hidden="true">
        <v-icon size="14" icon="mdi-lightning-bolt-outline" />
      </span>
      <div class="live-refresh-control__copy">
        <div class="live-refresh-control__label">Auto</div>
        <div class="live-refresh-control__meta">
          <span
            class="live-refresh-control__dot"
            :class="{ 'live-refresh-control__dot--on': liveEnabledState }"
            aria-hidden="true"
          />
          {{ liveEnabledState ? selectedIntervalLabel : "Off" }}
        </div>
      </div>
      <v-switch
        v-model="liveEnabledModel"
        color="primary"
        inset
        hide-details
        density="compact"
        name="live_refresh_toggle"
        class="live-refresh-control__switch"
      />
    </div>

    <v-btn
      v-if="showManual"
      size="small"
      variant="outlined"
      color="primary"
      prepend-icon="mdi-refresh"
      class="live-refresh-control__refresh"
      @click="emitRefresh"
    >
      {{ refreshLabel }}
    </v-btn>

    <v-menu v-if="showLive" location="bottom end" :close-on-content-click="false">
      <template #activator="{ props }">
        <v-btn
          v-bind="props"
          size="small"
          variant="outlined"
          color="secondary"
          icon
          rounded="lg"
          class="live-refresh-control__settings"
          :aria-label="menuAriaLabel"
        >
          <v-icon icon="mdi-tune-variant" />
        </v-btn>
      </template>

      <v-card class="pa-4 live-refresh-control__menu" min-width="280" rounded="lg">
        <div class="d-flex align-start justify-space-between ga-3 mb-4">
          <div>
            <div class="text-subtitle-2">Auto refresh</div>
            <div class="text-caption text-medium-emphasis mt-1">
              {{ liveEnabledState ? `Refreshing every ${selectedIntervalLabel} while idle.` : "Disabled until you turn it on." }}
            </div>
          </div>
          <v-switch
            v-model="liveEnabledModel"
            color="primary"
            inset
            hide-details
            density="compact"
            name="live_refresh_enabled"
            class="live-refresh-control__menu-switch"
          />
        </div>

        <v-select
          v-model="intervalMs"
          :items="intervalOptionsNormalized"
          label="Interval"
          name="live_refresh_interval"
          item-title="label"
          item-value="value"
          variant="outlined"
          density="comfortable"
          :disabled="!liveEnabledState"
          hide-details
          class="mb-3"
        />

        <v-btn
          block
          variant="tonal"
          color="primary"
          prepend-icon="mdi-refresh"
          @click="emitRefresh"
        >
          Refresh now
        </v-btn>

        <div class="text-caption text-medium-emphasis mt-3">
          Auto refresh only runs while the panel is idle.
        </div>
      </v-card>
    </v-menu>
  </div>
</template>

<script>
const DEFAULT_INTERVALS = [
  { label: "10s", value: 10000 },
  { label: "15s", value: 15000 },
  { label: "30s", value: 30000 },
  { label: "1m", value: 60000 },
  { label: "5m", value: 300000 },
];

export default {
  name: "LiveRefreshControl",
  props: {
    loading: {
      type: Boolean,
      default: false,
    },
    showManual: {
      type: Boolean,
      default: true,
    },
    showLive: {
      type: Boolean,
      default: false,
    },
    refreshLabel: {
      type: String,
      default: "Refresh",
    },
    menuAriaLabel: {
      type: String,
      default: "Open auto refresh settings",
    },
    liveEnabled: {
      type: Boolean,
      default: false,
    },
    defaultIntervalMs: {
      type: Number,
      default: 10000,
    },
    intervalOptions: {
      type: Array,
      default: () => DEFAULT_INTERVALS,
    },
  },
  emits: ["refresh", "update:liveEnabled"],
  data() {
    return {
      liveEnabledState: false,
      intervalMs: 10000,
      timerId: null,
    };
  },
  computed: {
    hasControls() {
      return this.showManual || this.showLive;
    },
    liveEnabledModel: {
      get() {
        return this.liveEnabledState;
      },
      set(value) {
        const normalized = Boolean(value);
        this.liveEnabledState = normalized;
        this.$emit("update:liveEnabled", normalized);
      },
    },
    intervalOptionsNormalized() {
      const options = Array.isArray(this.intervalOptions) ? this.intervalOptions : DEFAULT_INTERVALS;
      return options
        .map((item) => {
          if (item && typeof item === "object") {
            const value = Number(item.value);
            const label = String(item.label || "").trim();
            if (!Number.isFinite(value) || value <= 0) return null;
            return { label: label || this.formatIntervalLabel(value), value };
          }
          const value = Number(item);
          if (!Number.isFinite(value) || value <= 0) return null;
          return { label: this.formatIntervalLabel(value), value };
        })
        .filter(Boolean);
    },
    selectedIntervalLabel() {
      const match = this.intervalOptionsNormalized.find((item) => Number(item.value) === Number(this.intervalMs));
      if (match) return match.label;
      return this.formatIntervalLabel(this.intervalMs);
    },
  },
  watch: {
    liveEnabledState() {
      this.restartTimer(true);
    },
    intervalMs() {
      this.restartTimer(false);
    },
    showLive() {
      this.restartTimer(false);
    },
    loading() {
      if (!this.liveEnabledState) return;
      if (!this.timerId) {
        this.scheduleNext();
      }
    },
    defaultIntervalMs: {
      immediate: true,
      handler(value) {
        const parsed = Number(value);
        if (Number.isFinite(parsed) && parsed > 0) {
          this.intervalMs = parsed;
        }
      },
    },
    liveEnabled: {
      immediate: true,
      handler(value) {
        this.liveEnabledState = Boolean(value);
      },
    },
  },
  mounted() {
    if (this.showLive && this.liveEnabledState) {
      this.scheduleNext();
    }
  },
  beforeUnmount() {
    this.clearTimer();
  },
  methods: {
    formatIntervalLabel(value) {
      const numeric = Number(value);
      if (!Number.isFinite(numeric) || numeric <= 0) return "10s";
      if (numeric % 60000 === 0) {
        const minutes = numeric / 60000;
        return minutes === 1 ? "1m" : `${minutes}m`;
      }
      return `${Math.round(numeric / 1000)}s`;
    },
    emitRefresh() {
      this.$emit("refresh");
    },
    clearTimer() {
      if (this.timerId) {
        clearTimeout(this.timerId);
        this.timerId = null;
      }
    },
    restartTimer(refreshImmediately) {
      this.clearTimer();
      if (!this.showLive || !this.liveEnabledState) return;
      if (refreshImmediately && !this.loading) {
        this.$emit("refresh");
      }
      this.scheduleNext();
    },
    scheduleNext() {
      this.clearTimer();
      if (!this.showLive || !this.liveEnabledState) return;
      const delay = Math.max(10000, Number(this.intervalMs) || 10000);
      this.timerId = setTimeout(() => {
        this.timerId = null;
        if (this.showLive && this.liveEnabledState && !this.loading) {
          this.$emit("refresh");
        }
        this.scheduleNext();
      }, delay);
    },
  },
};
</script>

<style scoped>
.live-refresh-control {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.live-refresh-control__toggle-shell {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  min-height: 32px;
  padding: 4px 6px 4px 8px;
  border: 1px solid rgba(255, 170, 73, 0.72);
  border-radius: 999px;
  background: linear-gradient(180deg, rgba(18, 26, 39, 0.94), rgba(10, 16, 27, 0.96));
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
}

.live-refresh-control__spark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  border-radius: 999px;
  color: rgba(255, 182, 87, 0.96);
  background: rgba(255, 170, 73, 0.12);
}

.live-refresh-control__copy {
  display: flex;
  flex-direction: column;
  gap: 0;
  min-width: 0;
}

.live-refresh-control__label {
  color: rgba(239, 244, 251, 0.96);
  font-size: 0.66rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  line-height: 1.05;
}

.live-refresh-control__meta {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  color: rgba(192, 204, 221, 0.9);
  font-size: 0.7rem;
  font-weight: 600;
  line-height: 1.05;
}

.live-refresh-control__dot {
  width: 6px;
  height: 6px;
  border-radius: 999px;
  background: rgba(122, 134, 152, 0.9);
  box-shadow: 0 0 0 0 rgba(122, 134, 152, 0.18);
}

.live-refresh-control__dot--on {
  background: rgba(76, 201, 240, 0.96);
  box-shadow: 0 0 0 0 rgba(76, 201, 240, 0.28);
  animation: live-refresh-pulse 1.9s ease-in-out infinite;
}

.live-refresh-control__switch {
  margin: 0;
}

.live-refresh-control__switch :deep(.v-selection-control) {
  min-height: 0;
}

.live-refresh-control__switch :deep(.v-switch__track) {
  opacity: 1;
}

.live-refresh-control__switch :deep(.v-selection-control__wrapper) {
  width: 38px;
  height: 24px;
}

.live-refresh-control__switch :deep(.v-switch__thumb) {
  transform: scale(0.82);
}

.live-refresh-control__refresh {
  min-width: 0;
}

.live-refresh-control__refresh :deep(.v-btn__content) {
  font-size: 0.76rem;
  font-weight: 700;
}

.live-refresh-control__settings {
  flex: 0 0 auto;
}

.live-refresh-control__menu-switch {
  margin-top: -2px;
}

.live-refresh-control__menu {
  border: 1px solid rgba(104, 178, 221, 0.2);
  background: linear-gradient(180deg, rgba(7, 14, 24, 0.98), rgba(4, 10, 18, 0.98));
  box-shadow: 0 18px 38px rgba(2, 8, 14, 0.34);
}

@media (max-width: 780px) {
  .live-refresh-control {
    width: 100%;
    justify-content: flex-end;
  }

  .live-refresh-control__toggle-shell {
    flex: 1 1 auto;
    justify-content: space-between;
  }
}

@keyframes live-refresh-pulse {
  0% {
    box-shadow: 0 0 0 0 rgba(76, 201, 240, 0.28);
  }
  70% {
    box-shadow: 0 0 0 8px rgba(76, 201, 240, 0);
  }
  100% {
    box-shadow: 0 0 0 0 rgba(76, 201, 240, 0);
  }
}
</style>
