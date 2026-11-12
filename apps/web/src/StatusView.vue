<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();
const status = ref<"checking" | "ready" | "unavailable">("checking");

async function checkReadiness() {
  status.value = "checking";
  try {
    const response = await fetch("/api/v1/health/ready", {
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    const payload: unknown = response.ok ? await response.json() : null;
    status.value =
      payload &&
      typeof payload === "object" &&
      "status" in payload &&
      payload.status === "ok"
        ? "ready"
        : "unavailable";
  } catch {
    status.value = "unavailable";
  }
}

onMounted(checkReadiness);
</script>

<template>
  <h1 class="text-3xl font-semibold">{{ t("title") }}</h1>
  <p class="my-5" role="status">{{ t(status) }}</p>
  <button
    class="btn btn-outline"
    type="button"
    :disabled="status === 'checking'"
    @click="checkReadiness"
  >
    {{ t("retry") }}
  </button>
</template>
