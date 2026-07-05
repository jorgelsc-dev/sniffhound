<template>
  <v-card :variant="variant" class="pa-6 data-panel">
    <div
      v-if="showHeader"
      class="d-flex align-center justify-space-between flex-wrap ga-2 mb-4 panel-head"
    >
      <div class="d-flex align-center ga-3">
        <span class="panel-pulse"></span>
        <div>
          <div class="text-subtitle-1 font-weight-medium">{{ title }}</div>
          <div v-if="subtitle" class="text-body-2 text-medium-emphasis">
            {{ subtitle }}
          </div>
        </div>
      </div>
      <div class="d-flex align-center ga-2">
        <v-chip v-if="lastUpdated" size="small" variant="outlined" color="info">
          {{ lastUpdated }}
        </v-chip>
        <LiveRefreshControl
          v-if="showRefresh || liveRefresh"
          :loading="loading"
          :show-manual="showRefresh"
          :show-live="liveRefresh"
          :live-enabled="liveEnabled"
          :refresh-label="refreshLabel"
          @update:liveEnabled="$emit('update:liveEnabled', $event)"
          @refresh="$emit('refresh')"
        />
      </div>
    </div>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">
      {{ error }}
    </v-alert>

    <transition name="panel-fade">
      <div v-if="loading" class="panel-loader-shell">
        <BrandMark :size="58" animated framed />
        <div class="panel-loader-copy">
          <div class="panel-loader-title">Loading live panel</div>
          <div class="panel-loader-text">
            The official brand mark keeps moving while this view refreshes.
          </div>
        </div>
      </div>
    </transition>

    <div class="panel-body">
      <div
        v-if="!loading || keepContentOnLoading"
        class="panel-content"
        :class="{ 'panel-content--loading': loading && keepContentOnLoading }"
      >
        <slot />
      </div>
    </div>
  </v-card>
</template>

<script>
import BrandMark from "../brand/BrandMark.vue";
import LiveRefreshControl from "./LiveRefreshControl.vue";

export default {
  name: "DataPanel",
  components: {
    BrandMark,
    LiveRefreshControl,
  },
  props: {
    title: {
      type: String,
      required: true,
    },
    subtitle: {
      type: String,
      default: "",
    },
    loading: {
      type: Boolean,
      default: false,
    },
    showSkeleton: {
      type: Boolean,
      default: false,
    },
    keepContentOnLoading: {
      type: Boolean,
      default: true,
    },
    error: {
      type: String,
      default: "",
    },
    lastUpdated: {
      type: String,
      default: "",
    },
    showRefresh: {
      type: Boolean,
      default: false,
    },
    liveRefresh: {
      type: Boolean,
      default: false,
    },
    liveEnabled: {
      type: Boolean,
      default: false,
    },
    showHeader: {
      type: Boolean,
      default: true,
    },
    refreshLabel: {
      type: String,
      default: "Refresh",
    },
    variant: {
      type: String,
      default: "outlined",
    },
  },
  emits: ["refresh", "update:liveEnabled"],
};
</script>

<style scoped>
.data-panel {
  border-radius: 18px;
  overflow: hidden;
}

.panel-head {
  padding-bottom: 10px;
  border-bottom: 1px solid rgba(104, 178, 221, 0.14);
}

.panel-pulse {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: rgba(var(--brand-sky-rgb), 0.92);
  box-shadow: 0 0 0 0 rgba(var(--brand-sky-rgb), 0.32);
  animation: panel-pulse 2.1s ease-in-out infinite;
}

.panel-loader-shell {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 16px;
  padding: 14px 16px;
  border-radius: 16px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.16);
  background:
    radial-gradient(circle at 14% 26%, rgba(var(--brand-cyan-rgb), 0.13), transparent 38%),
    radial-gradient(circle at 90% 82%, rgba(var(--brand-violet-rgb), 0.14), transparent 44%),
    linear-gradient(145deg, rgba(10, 17, 28, 0.9), rgba(8, 14, 23, 0.82));
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03), 0 16px 32px rgba(2, 7, 13, 0.18);
}

.panel-loader-copy {
  min-width: 0;
}

.panel-loader-title {
  font-family: var(--font-heading);
  font-size: 0.76rem;
  font-weight: 680;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: rgba(236, 245, 255, 0.95);
}

.panel-loader-text {
  margin-top: 4px;
  color: var(--text-dim);
  font-size: 0.84rem;
  line-height: 1.45;
}

.panel-body {
  position: relative;
  min-height: 78px;
}

.panel-content {
  transition: opacity 0.18s ease;
}

.panel-content--loading {
  opacity: 0.54;
}

@keyframes panel-pulse {
  0%,
  100% {
    box-shadow: 0 0 0 0 rgba(var(--brand-sky-rgb), 0.3);
  }
  50% {
    box-shadow: 0 0 0 8px rgba(var(--brand-sky-rgb), 0);
  }
}

.panel-fade-enter-active,
.panel-fade-leave-active {
  transition: opacity 0.2s ease;
}

.panel-fade-enter-from,
.panel-fade-leave-to {
  opacity: 0;
}

@media (max-width: 600px) {
  .panel-loader-shell {
    align-items: flex-start;
  }
}

</style>
