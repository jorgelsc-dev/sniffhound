import { createRouter, createWebHistory } from "vue-router";
import { appBaseUrl } from "../utils/runtimeEnv";

const routes = [
  { path: "/", name: "dashboard", component: () => import("../views/DashboardView.vue") },
  { path: "/radar", name: "radar", component: () => import("../views/RadarView.vue") },
  { path: "/investigate", name: "investigate", component: () => import("../views/InvestigateView.vue") },
  { path: "/sniffer", name: "sniffer", component: () => import("../views/SnifferView.vue") },
  { path: "/soc", name: "soc", component: () => import("../views/SocView.vue") },
  {
    path: "/protocols/:proto?",
    name: "protocols",
    alias: ["/protocolos", "/protocolos/:proto?"],
    component: () => import("../views/ProtocolsView.vue"),
  },
  { path: "/honeypot", name: "honeypot", component: () => import("../views/HoneypotView.vue") },
  { path: "/targets", name: "targets", component: () => import("../views/TargetsView.vue") },
  { path: "/sessions", redirect: "/targets" },
  { path: "/intel", redirect: "/investigate" },
  { path: "/ports", redirect: "/sniffer" },
  { path: "/banners", redirect: "/honeypot" },
  { path: "/:pathMatch(.*)*", redirect: "/" },
];

const router = createRouter({
  history: createWebHistory(appBaseUrl()),
  routes,
  scrollBehavior() {
    return { left: 0, top: 0 };
  },
});

export default router;
