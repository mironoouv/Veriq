<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();
const live = ref<boolean | null>(null);
const ready = ref<boolean | null>(null);

async function probe(kind: "live" | "ready"): Promise<boolean> {
  try {
    const response = await fetch(`/api/v1/health/${kind}`, {
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    const payload: unknown = response.ok ? await response.json() : null;
    return (
      payload !== null &&
      typeof payload === "object" &&
      "status" in payload &&
      payload.status === "ok"
    );
  } catch {
    return false;
  }
}

async function checkStatus() {
  live.value = null;
  ready.value = null;
  const [api, system] = await Promise.all([probe("live"), probe("ready")]);
  live.value = api;
  ready.value = system;
}

onMounted(checkStatus);
</script>

<template>
  <h1 class="text-3xl font-semibold">{{ t("title") }}</h1>
  <p class="mt-5" role="status" :aria-label="t('liveness')">
    {{ t(live === null ? "checking" : live ? "live" : "offline") }}
  </p>
  <p class="mb-5" role="status" :aria-label="t('readiness')">
    {{ t(ready === null ? "checking" : ready ? "ready" : "unavailable") }}
  </p>
  <button
    class="btn btn-outline"
    type="button"
    :disabled="live === null || ready === null"
    @click="checkStatus"
  >
    {{ t("retry") }}
  </button>
</template>
