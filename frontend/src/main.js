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
          background: "#0b1016",
          surface: "#141b24",
          primary: "#34e6ff",
          secondary: "#ff9f43",
          error: "#ff5468",
          info: "#4a88ff",
          success: "#35e6b1",
          warning: "#f3b14b",
        },
      },
    },
  },
});

store.initApiBase();
store.bootstrap();

createApp(App).use(vuetify).use(router).mount("#app");
