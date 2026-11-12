<script setup lang="ts">
import { watch } from "vue";
import { useI18n } from "vue-i18n";
import { RouterLink, RouterView } from "vue-router";

const { locale, t } = useI18n();
watch(locale, (value) => (document.documentElement.lang = value));
</script>

<template>
  <header class="border-b border-base-300">
    <nav class="mx-auto flex max-w-4xl flex-wrap items-center gap-4 px-5 py-4">
      <RouterLink
        class="link link-hover font-semibold"
        to="/"
        :aria-label="'Veriq · ' + t('home')"
      >
        Veriq
      </RouterLink>
      <label class="ml-auto flex items-center gap-2">
        {{ t("language") }}
        <select v-model="locale" class="select select-sm w-auto">
          <option value="ru" lang="ru">Русский</option>
          <option value="en" lang="en">English</option>
        </select>
      </label>
    </nav>
  </header>
  <main class="mx-auto max-w-4xl px-5 py-12">
    <RouterView />
  </main>
</template>
