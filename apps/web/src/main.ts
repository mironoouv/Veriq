import { createPinia } from "pinia";
import { createApp } from "vue";
import { createI18n } from "vue-i18n";
import { createRouter, createWebHistory } from "vue-router";
import AcademicCatalogView from "./AcademicCatalogView.vue";
import App from "./App.vue";
import StatusView from "./StatusView.vue";
import "./style.css";

const messages = {
  ru: {
    home: "Состояние",
    language: "Язык",
    title: "Состояние Veriq",
    checking: "Проверяем подключение…",
    liveness: "Доступность API",
    readiness: "Готовность системы",
    live: "API отвечает.",
    offline: "API недоступен.",
    ready: "API, PostgreSQL и Redis доступны.",
    unavailable: "Проверка доступности не прошла.",
    retry: "Проверить снова",
  },
  en: {
    home: "Status",
    language: "Language",
    title: "Veriq status",
    checking: "Checking the connection…",
    liveness: "API liveness",
    readiness: "System readiness",
    live: "The API is responding.",
    offline: "The API is unavailable.",
    ready: "The API, PostgreSQL and Redis are available.",
    unavailable: "The readiness check failed.",
    retry: "Check again",
  },
};

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", component: StatusView },
    { path: "/status", component: StatusView },
    { path: "/academic/:organizationId", component: AcademicCatalogView },
    { path: "/:pathMatch(.*)*", redirect: "/" },
  ],
});

createApp(App)
  .use(createPinia())
  .use(
    createI18n({ legacy: false, locale: "ru", fallbackLocale: "en", messages }),
  )
  .use(router)
  .mount("#app");
