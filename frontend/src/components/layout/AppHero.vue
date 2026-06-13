<template>
  <v-sheet class="hero-banner" rounded="xl">
    <v-row align="center" class="pa-6 pa-md-8">
      <v-col cols="12" md="8">
        <div class="text-overline text-primary">Network telemetry</div>
        <div class="text-h4 text-md-h3 font-weight-bold">SniffHound Control Room</div>
        <div class="text-body-1 text-medium-emphasis mt-2">
          Operate the sniffer and honeypot from one place, then drill into dedicated traffic
          views for passive capture, inbound honeypot hits, and session inventory.
        </div>
        <div class="d-flex flex-wrap ga-3 mt-4">
          <v-btn color="primary" variant="flat" to="/sniffer">Sniffer</v-btn>
          <v-btn color="warning" variant="outlined" to="/honeypot">Honeypot</v-btn>
          <v-btn color="info" variant="outlined" to="/targets">Sessions</v-btn>
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
      <v-col cols="12" md="4">
        <v-card variant="tonal" color="surface" class="pa-5 api-card">
          <div class="control-stack">
            <section class="control-box">
              <div class="d-flex align-center justify-space-between ga-3">
                <div>
                  <div class="text-subtitle-2 font-weight-medium">Runtime Modes</div>
                  <div class="text-caption text-medium-emphasis">
                    Both engines stay visible here. Start one or stop the active one.
                  </div>
                </div>
                <v-chip size="small" :color="runtimeChipColor" variant="tonal" prepend-icon="mdi-toggle-switch">
                  {{ runtimeModeLabel }}
                </v-chip>
              </div>

              <div class="runtime-table mt-4">
                <div class="runtime-table__head">
                  <span>Mode</span>
                  <span>Status</span>
                  <span>Action</span>
                </div>
                <div
                  v-for="row in runtimeRows"
                  :key="row.key"
                  class="runtime-table__row"
                >
                  <div class="runtime-table__modecell">
                    <div class="runtime-table__mode">{{ row.label }}</div>
                    <div class="runtime-table__meta">{{ row.summary }}</div>
                  </div>
                  <v-chip
                    size="small"
                    :color="row.statusColor"
                    variant="tonal"
                  >
                    {{ row.statusLabel }}
                  </v-chip>
                  <v-btn
                    size="small"
                    :color="row.actionColor"
                    variant="outlined"
                    :loading="runtimeSubmitting === row.mode"
                    @click="toggleRuntimeMode(row)"
                  >
                    {{ row.actionLabel }}
                  </v-btn>
                </div>
              </div>

              <v-alert
                v-if="runtimeError"
                class="mt-3 control-alert control-alert--warning"
                type="warning"
                variant="tonal"
                density="comfortable"
              >
                {{ runtimeError }}
              </v-alert>
            </section>

            <section class="control-box">
              <div class="d-flex align-center justify-space-between ga-3">
                <div>
                  <div class="text-subtitle-2 font-weight-medium">Sniff Interfaces</div>
                  <div class="text-caption text-medium-emphasis mt-1">
                    Select one or more interfaces. Leave it empty to sniff every visible interface.
                  </div>
                </div>
                <v-chip size="small" color="info" variant="outlined">
                  {{ selectedInterfaces.length ? `${selectedInterfaces.length} selected` : "All" }}
                </v-chip>
              </div>

              <v-select
                class="mt-3"
                :model-value="selectedInterfaces"
                :items="snifferInterfaceOptions"
                label="Interfaces"
                item-title="label"
                item-value="value"
                variant="outlined"
                density="comfortable"
                hide-details="auto"
                multiple
                chips
                clearable
                closable-chips
                :loading="interfaceSubmitting"
                :error-messages="interfaceError ? [interfaceError] : []"
                @update:model-value="updateSnifferInterfaces"
              />

              <div class="text-caption text-medium-emphasis mt-2">
                {{ snifferInterfaceStatus }}
              </div>
              <v-alert
                v-if="snifferBlocked"
                class="mt-3 control-alert"
                type="error"
                variant="tonal"
                density="comfortable"
              >
                {{ snifferErrorSummary }}
              </v-alert>
            </section>
          </div>
        </v-card>
      </v-col>
    </v-row>
  </v-sheet>
</template>

<script>
import store from "../../state/appStore";

export default {
  name: "AppHero",
  data() {
    return {
      runtimeSubmitting: "",
      runtimeError: "",
      interfaceSubmitting: false,
      interfaceError: "",
    };
  },
  computed: {
    runtimeMode() {
      const runtime = store.state.runtime || {};
      return String(runtime.mode || store.state.runtimeMode || "sniffer").trim().toLowerCase() || "sniffer";
    },
    snifferRuntime() {
      const runtime = store.state.runtime || {};
      return runtime.sniffer && typeof runtime.sniffer === "object" ? runtime.sniffer : {};
    },
    honeypotRuntime() {
      const runtime = store.state.runtime || {};
      return runtime.honeypot && typeof runtime.honeypot === "object" ? runtime.honeypot : {};
    },
    runtimeModeLabel() {
      return this.runtimeMode === "honeypot" ? "Active: Honeypot" : "Active: Sniffer";
    },
    runtimeChipColor() {
      return this.runtimeMode === "honeypot" ? "warning" : "info";
    },
    runtimeRows() {
      return [
        this.buildRuntimeRow("sniffer", "Sniffer", this.snifferRuntime),
        this.buildRuntimeRow("honeypot", "Honeypot", this.honeypotRuntime),
      ];
    },
    selectedInterfaces() {
      const selected = Array.isArray(this.snifferRuntime.selected_interfaces)
        ? this.snifferRuntime.selected_interfaces
        : [];
      return [...new Set(selected.map((item) => String(item || "").trim()).filter(Boolean))];
    },
    snifferInterfaceOptions() {
      const available = Array.isArray(this.snifferRuntime.available_interfaces)
        ? this.snifferRuntime.available_interfaces
        : [];
      const values = [...new Set(available.map((item) => String(item || "").trim()).filter(Boolean))].sort();
      return values.map((value) => ({ label: value, value }));
    },
    snifferErrors() {
      const errors = this.snifferRuntime.errors && typeof this.snifferRuntime.errors === "object"
        ? this.snifferRuntime.errors
        : {};
      return Object.entries(errors)
        .map(([name, message]) => ({
          name: String(name || "").trim(),
          message: String(message || "").trim(),
        }))
        .filter((item) => item.name && item.message);
    },
    snifferBlocked() {
      return String(this.snifferRuntime.capture_state || "").trim().toLowerCase() === "blocked";
    },
    selectedInterfacesSummary() {
      if (!this.selectedInterfaces.length) return "all visible interfaces";
      if (this.selectedInterfaces.length <= 3) return this.selectedInterfaces.join(", ");
      return `${this.selectedInterfaces.length} selected interfaces`;
    },
    snifferErrorSummary() {
      if (!this.snifferErrors.length) {
        return "Packet capture is blocked on every selected interface.";
      }
      const sample = this.snifferErrors
        .slice(0, 2)
        .map((item) => `${item.name}: ${item.message}`)
        .join(" | ");
      if (this.snifferErrors.length <= 2) {
        return `Packet capture blocked. ${sample}`;
      }
      return `Packet capture blocked. ${sample} | +${this.snifferErrors.length - 2} more`;
    },
    snifferInterfaceStatus() {
      const selectedLabel = this.selectedInterfacesSummary;
      const active = Array.isArray(this.snifferRuntime.interfaces)
        ? this.snifferRuntime.interfaces.map((item) => String(item || "").trim()).filter(Boolean)
        : [];
      if (this.snifferBlocked) {
        return `Capture blocked on ${active.length || this.selectedInterfaces.length || 0} interfaces`;
      }
      if (String(this.snifferRuntime.capture_state || "").trim().toLowerCase() === "running" && active.length > 1) {
        return `Capturing on ${active.length} interfaces`;
      }
      if (String(this.snifferRuntime.capture_state || "").trim().toLowerCase() === "running" && active.length === 1) {
        return `Capturing on ${active[0]}`;
      }
      return `Ready to capture on ${selectedLabel}`;
    },
  },
  methods: {
    buildRuntimeRow(mode, label, engine) {
      const statusLabel = this.describeRuntimeStatus(mode, engine);
      const isActive = this.runtimeMode === mode;
      const isRunning = Boolean(engine && engine.running);
      return {
        key: mode,
        mode,
        label,
        engine,
        isActive,
        statusLabel,
        statusColor: this.runtimeStatusColor(statusLabel, isActive),
        summary: this.describeRuntimeSummary(mode, engine),
        actionLabel: isActive && isRunning ? "Stop" : "Start",
        actionColor: isActive && isRunning ? "warning" : mode === "honeypot" ? "warning" : "primary",
      };
    },
    describeRuntimeStatus(mode, engine) {
      if (mode === "sniffer") {
        const captureState = String(engine.capture_state || "").trim().toLowerCase();
        if (captureState === "blocked") return "Blocked";
        if (captureState === "running") return "Running";
        return this.runtimeMode === "sniffer" ? "Idle" : "Ready";
      }
      if (this.runtimeMode === "honeypot" && engine && engine.running) {
        return "Running";
      }
      return this.runtimeMode === "honeypot" ? "Idle" : "Ready";
    },
    runtimeStatusColor(status, isActive) {
      if (status === "Blocked") return "error";
      if (status === "Running") return isActive ? "success" : "info";
      if (status === "Idle") return "warning";
      return "secondary";
    },
    describeRuntimeSummary(mode, engine) {
      if (mode === "sniffer") {
        if (this.snifferBlocked) {
          return this.snifferErrorSummary;
        }
        if (String(engine.capture_state || "").trim().toLowerCase() === "running") {
          const active = Array.isArray(engine.interfaces) ? engine.interfaces.length : 0;
          if (active > 1) return `${active} interfaces active`;
          if (active === 1) return `${engine.interfaces[0]} active`;
          return "Capturing";
        }
        return `Interfaces: ${this.selectedInterfacesSummary}`;
      }
      const listeners = Array.isArray(engine.listeners) ? engine.listeners.length : 0;
      if (this.runtimeMode === "honeypot" && engine && engine.running) {
        return `${listeners} listeners active`;
      }
      return listeners ? `${listeners} listeners configured` : "Ready to expose honeypot services";
    },
    toggleRuntimeMode(row) {
      if (!row || !row.mode || this.runtimeSubmitting) return;
      const action = row.isActive && row.engine && row.engine.running ? "stop" : "start";
      this.runtimeError = "";
      this.runtimeSubmitting = row.mode;
      store
        .controlRuntimeMode(row.mode, action)
        .catch((err) => {
          this.runtimeError = err.message || `Failed to ${action} ${row.label.toLowerCase()}`;
        })
        .finally(() => {
          this.runtimeSubmitting = "";
        });
    },
    updateSnifferInterfaces(value) {
      const normalized = Array.isArray(value)
        ? [...new Set(value.map((item) => String(item || "").trim()).filter(Boolean))]
        : [];
      if (this.interfaceSubmitting) {
        return;
      }
      const current = [...this.selectedInterfaces].sort();
      const incoming = [...normalized].sort();
      if (incoming.length === current.length && incoming.every((item, index) => item === current[index])) {
        return;
      }
      this.interfaceError = "";
      this.interfaceSubmitting = true;
      store
        .setSnifferInterfaces(normalized)
        .catch((err) => {
          this.interfaceError = err.message || "Failed to update interface";
        })
        .finally(() => {
          this.interfaceSubmitting = false;
        });
    },
  },
};
</script>

<style scoped>
.hero-banner {
  position: relative;
  overflow: hidden;
  background: radial-gradient(
      110% 140% at -8% -24%,
      rgba(53, 196, 237, 0.24),
      transparent 58%
    ),
    radial-gradient(
      90% 110% at 110% -30%,
      rgba(244, 176, 79, 0.18),
      transparent 63%
    ),
    linear-gradient(122deg, rgba(13, 21, 32, 0.98), rgba(8, 14, 23, 0.98));
  border: 1px solid rgba(88, 176, 224, 0.26);
  box-shadow: 0 26px 50px rgba(3, 7, 14, 0.42), inset 0 0 0 1px rgba(255, 255, 255, 0.03);
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
    rgba(90, 182, 228, 0.2),
    rgba(90, 182, 228, 0)
  );
  pointer-events: none;
}

.api-card {
  border: 1px solid rgba(118, 191, 232, 0.24);
  background: linear-gradient(180deg, rgba(16, 26, 39, 0.9), rgba(11, 18, 28, 0.82));
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.03);
}

.control-stack {
  display: grid;
  gap: 14px;
}

.control-box {
  padding: 16px;
  border-radius: 18px;
  border: 1px solid rgba(116, 194, 236, 0.16);
  background:
    linear-gradient(180deg, rgba(17, 28, 41, 0.92), rgba(11, 20, 31, 0.8)),
    radial-gradient(circle at top right, rgba(74, 177, 222, 0.1), transparent 48%);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04), 0 14px 26px rgba(2, 7, 13, 0.18);
}

.runtime-table {
  display: grid;
  gap: 10px;
}

.runtime-table__head,
.runtime-table__row {
  display: grid;
  grid-template-columns: minmax(0, 1.6fr) auto auto;
  gap: 10px;
  align-items: center;
}

.runtime-table__head {
  padding: 0 2px;
  color: rgba(197, 214, 232, 0.7);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.runtime-table__row {
  padding: 12px 12px 12px 14px;
  border-radius: 14px;
  border: 1px solid rgba(118, 191, 232, 0.12);
  background: linear-gradient(180deg, rgba(10, 19, 30, 0.82), rgba(8, 15, 25, 0.76));
}

.runtime-table__mode {
  font-weight: 700;
  letter-spacing: 0.02em;
}

.runtime-table__meta {
  margin-top: 4px;
  color: rgba(197, 214, 232, 0.7);
  font-size: 0.8rem;
  line-height: 1.4;
}

.usage-notice {
  border: 1px solid rgba(255, 196, 118, 0.18);
  background: linear-gradient(180deg, rgba(38, 26, 14, 0.74), rgba(26, 20, 12, 0.54)) !important;
}

.hero-banner :deep(.v-btn) {
  letter-spacing: 0.04em;
}

.control-box :deep(.v-field) {
  border-radius: 14px;
  background: rgba(7, 14, 23, 0.54);
}

.control-box :deep(.v-chip) {
  letter-spacing: 0.03em;
}

.control-alert {
  border: 1px solid rgba(255, 124, 124, 0.18);
  background: linear-gradient(180deg, rgba(52, 15, 18, 0.78), rgba(29, 12, 15, 0.66)) !important;
}

.control-alert--warning {
  border-color: rgba(255, 196, 118, 0.18);
  background: linear-gradient(180deg, rgba(57, 33, 11, 0.78), rgba(32, 22, 10, 0.66)) !important;
}

@media (max-width: 600px) {
  .runtime-table__head {
    display: none;
  }

  .runtime-table__row {
    grid-template-columns: 1fr;
  }
}
</style>
