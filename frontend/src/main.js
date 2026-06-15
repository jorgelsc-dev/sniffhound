import { createApp } from "vue";
import App from "./App.vue";
import "./styles/app.css";

import "vuetify/styles";
import "@mdi/font/css/materialdesignicons.css";
import { createVuetify } from "vuetify";
import { aliases, mdi } from "vuetify/iconsets/mdi";
import router from "./router";
import store from "./state/appStore";

const vuetify = createVuetify({
  icons: {
    defaultSet: "mdi",
    aliases,
    sets: { mdi },
  },
  theme: {
    defaultTheme: "sniffhoundDark",
    themes: {
      sniffhoundDark: {
        dark: true,
        colors: {
          background: "#05080f",
          surface: "#111827",
          primary: "#34e6ff",
          secondary: "#8d73ff",
          error: "#ff647a",
          info: "#4d8cff",
          success: "#43d7be",
          warning: "#f3b15b",
        },
      },
    },
  },
});

store.initApiBase();
store.bootstrap();

createApp(App).use(vuetify).use(router).mount("#app");
