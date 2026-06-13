<template>
  <v-app class="sniffhound-app">
    <AppSidebar
      :open="drawer"
      :nav-items="navItems"
      @update:open="drawer = $event"
    />

    <AppTopBar
      :nav-items="navItems"
      :auth-required="authRequired"
      :auth-status="authStatus"
      :ws-status="wsStatus"
      @open-drawer="drawer = true"
      @open-auth="openAuthPrompt"
    />

    <v-main class="app-main">
      <v-container class="app-container">
        <div v-if="canRenderViews">
          <AppHero v-if="showHero" />

          <div :class="showHero ? 'mt-8' : 'mt-3'">
            <router-view v-slot="{ Component }">
              <transition name="view-fade" mode="out-in">
                <component :is="Component" />
              </transition>
            </router-view>
          </div>
        </div>

        <div v-else class="auth-stage">
          <v-sheet class="auth-stage-card" rounded="xl" elevation="0">
            <div class="auth-stage-kicker">Protected Console</div>
            <h1 class="auth-stage-title">Autenticación requerida</h1>
            <p class="auth-stage-copy">
              Introduce el access token mostrado en la terminal para desbloquear el dashboard y
              reanudar HTTP y WebSocket.
            </p>
            <v-btn color="primary" size="large" variant="flat" @click="openAuthPrompt">
              Introducir token
            </v-btn>
            <v-alert
              v-if="authError"
              class="mt-5"
              type="warning"
              variant="tonal"
              density="comfortable"
            >
              {{ authError }}
            </v-alert>
          </v-sheet>
        </div>
      </v-container>
    </v-main>

    <v-dialog :model-value="authPromptOpen" persistent max-width="520">
      <v-card class="auth-dialog-card" rounded="xl">
        <div class="auth-dialog-topline" />
        <v-card-title class="text-h5 pt-6">Session Access Token</v-card-title>
        <v-card-text class="pt-4">
          <p class="auth-dialog-copy">
            Copia el token de 8 caracteres desde la terminal de `sniffhound`. Se guarda solo en
            `sessionStorage` y se borra cuando el backend responde `401` o el WebSocket devuelve
            `4401`.
          </p>
          <v-text-field
            ref="authInput"
            v-model="accessTokenInput"
            label="Access token"
            variant="outlined"
            density="comfortable"
            autocapitalize="off"
            autocomplete="one-time-code"
            spellcheck="false"
            :error-messages="authError ? [authError] : []"
            :loading="authSubmitting"
            @keyup.enter="submitAccessToken"
          />
        </v-card-text>
        <v-card-actions class="px-6 pb-6">
          <v-spacer />
          <v-btn
            color="primary"
            size="large"
            variant="flat"
            :loading="authSubmitting"
            @click="submitAccessToken"
          >
            Autenticar
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-app>
</template>

<script>
import { nextTick } from "vue";
import store from "./state/appStore";
import AppSidebar from "./components/layout/AppSidebar.vue";
import AppTopBar from "./components/layout/AppTopBar.vue";
import AppHero from "./components/layout/AppHero.vue";

export default {
  name: "App",
  components: {
    AppSidebar,
    AppTopBar,
    AppHero,
  },
  data() {
    return {
      store,
      drawer: false,
      accessTokenInput: "",
      authSubmitting: false,
      navItems: [
        { label: "Dashboard", to: "/", icon: "mdi-view-dashboard" },
        { label: "Radar", to: "/radar", icon: "mdi-radar" },
        { label: "Investigate", to: "/investigate", icon: "mdi-magnify" },
        { label: "Sniffer", to: "/sniffer", icon: "mdi-ethernet" },
        { label: "SOC", to: "/soc", icon: "mdi-shield-search" },
        { label: "Protocolos", to: "/protocols", icon: "mdi-shuffle-variant" },
        { label: "Honeypot", to: "/honeypot", icon: "mdi-shield-bug" },
        { label: "Sessions", to: "/targets", icon: "mdi-account-switch" },
      ],
    };
  },
  computed: {
    authError() {
      return this.store.state.authError || "";
    },
    authPromptOpen() {
      return Boolean(this.store.state.authPromptOpen);
    },
    authRequired() {
      return Boolean(this.store.state.authRequired);
    },
    authStatus() {
      return this.store.state.authStatus || "unknown";
    },
    canRenderViews() {
      if (!this.store.state.authReady) return false;
      if (!this.authRequired) return true;
      return this.authStatus === "authenticated";
    },
    wsStatus() {
      return this.store.state.wsStatus || "offline";
    },
    showHero() {
      if (!this.canRenderViews) return false;
      const name = String((this.$route && this.$route.name) || "").toLowerCase();
      return name === "dashboard";
    },
  },
  watch: {
    authPromptOpen: {
      immediate: true,
      handler(isOpen) {
        if (!isOpen) return;
        this.accessTokenInput = this.store.state.authToken || this.accessTokenInput || "";
        nextTick(() => {
          const field = this.$refs.authInput;
          if (field && typeof field.focus === "function") {
            field.focus();
          }
        });
      },
    },
  },
  methods: {
    openAuthPrompt() {
      this.accessTokenInput = this.store.state.authToken || this.accessTokenInput || "";
      this.store.openAuthPrompt();
    },
    submitAccessToken() {
      if (this.authSubmitting) return;
      this.authSubmitting = true;
      this.store
        .authenticateSessionToken(this.accessTokenInput)
        .then(() => {
          this.accessTokenInput = this.store.state.authToken || "";
        })
        .catch(() => null)
        .finally(() => {
          this.authSubmitting = false;
        });
    },
  },
};
</script>

<style scoped>
.app-container {
  max-width: 1560px;
  width: 100%;
}

.app-main {
  padding-bottom: 40px;
}

.auth-stage {
  min-height: calc(100vh - 180px);
  display: grid;
  place-items: center;
  padding: 28px 0;
}

.auth-stage-card {
  width: min(100%, 680px);
  padding: 34px;
  border: 1px solid rgba(52, 230, 255, 0.16);
  background:
    radial-gradient(circle at top right, rgba(255, 159, 67, 0.18), transparent 42%),
    linear-gradient(160deg, rgba(19, 29, 40, 0.94), rgba(11, 17, 24, 0.98));
}

.auth-stage-kicker {
  color: rgba(52, 230, 255, 0.9);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.18em;
  text-transform: uppercase;
}

.auth-stage-title {
  margin: 12px 0 10px;
  font-size: clamp(1.8rem, 4vw, 2.6rem);
  line-height: 1.05;
}

.auth-stage-copy,
.auth-dialog-copy {
  color: rgba(223, 233, 246, 0.78);
  line-height: 1.65;
}

.auth-dialog-card {
  overflow: hidden;
  border: 1px solid rgba(52, 230, 255, 0.16);
  background: linear-gradient(180deg, rgba(17, 24, 34, 0.98), rgba(11, 17, 24, 0.98));
}

.auth-dialog-topline {
  height: 6px;
  background: linear-gradient(90deg, #34e6ff 0%, #ff9f43 100%);
}

.view-fade-enter-active,
.view-fade-leave-active {
  transition: opacity 0.2s ease, transform 0.22s ease;
}

.view-fade-enter-from,
.view-fade-leave-to {
  opacity: 0;
  transform: translateY(6px);
}

@media (max-width: 959px) {
  .app-main {
    padding-bottom: 24px;
  }

  .auth-stage-card {
    padding: 24px;
  }
}
</style>
