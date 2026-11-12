import { createPinia } from "pinia";
import { createApp } from "vue";
import { createI18n } from "vue-i18n";
import { createRouter, createWebHistory } from "vue-router";
import App from "./App.vue";
import StatusView from "./StatusView.vue";
import "./style.css";

const messages = {
  ru: {
    home: "Состояние",
    language: "Язык",
    title: "Состояние Veriq",
    checking: "Проверяем подключение…",
    ready: "API, PostgreSQL и Redis доступны.",
    unavailable: "Проверка доступности не прошла.",
    retry: "Проверить снова",
  },
  en: {
    home: "Status",
    language: "Language",
    title: "Veriq status",
    checking: "Checking the connection…",
    ready: "The API, PostgreSQL and Redis are available.",
    unavailable: "The readiness check failed.",
    retry: "Check again",
  },
};

const router = createRouter({
  history: createWebHistory(),
  routes: [{ path: "/", component: StatusView }],
});

createApp(App)
  .use(createPinia())
  .use(
    createI18n({ legacy: false, locale: "ru", fallbackLocale: "en", messages }),
  )
  .use(router)
  .mount("#app");
