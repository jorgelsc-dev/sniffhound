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

    <div class="panel-body">
      <div class="panel-content">
        <slot />
      </div>
    </div>
  </v-card>
</template>

<script>
import LiveRefreshControl from "./LiveRefreshControl.vue";

export default {
  name: "DataPanel",
  components: {
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
  background: rgba(103, 205, 248, 0.9);
  box-shadow: 0 0 0 0 rgba(103, 205, 248, 0.32);
  animation: panel-pulse 2.1s ease-in-out infinite;
}

.panel-body {
  position: relative;
  min-height: 78px;
}

.panel-content {
  transition: opacity 0.18s ease;
}

@keyframes panel-pulse {
  0%,
  100% {
    box-shadow: 0 0 0 0 rgba(103, 205, 248, 0.3);
  }
  50% {
    box-shadow: 0 0 0 8px rgba(103, 205, 248, 0);
  }
}

</style>
