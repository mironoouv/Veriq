<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useRoute } from "vue-router";

interface CatalogItem {
  id: string;
  title: string;
  description: string | null;
  status: "active" | "archived";
  version: number;
}
interface CatalogPage {
  items: CatalogItem[];
  total: number;
  can_restore: boolean;
}

const { t } = useI18n({
  useScope: "local",
  messages: {
    ru: {
      catalog: "Учебная структура",
      courses: "Дисциплины",
      study_groups: "Группы",
      active: "Активные",
      archived: "Архив",
      search: "Поиск по названию",
      loading: "Загрузка…",
      empty: "Записей нет",
      denied: "Недостаточно прав для этой операции.",
      failed: "Не удалось выполнить запрос.",
      conflict: "Запись изменилась. Обновите список и повторите.",
      retry: "Обновить",
      create: "Создать",
      edit: "Редактировать",
      archive: "Архивировать",
      restore: "Восстановить",
      archiveQuestion: "Переместить «{title}» в архив?",
      title: "Название",
      description: "Описание",
      save: "Сохранить",
      cancel: "Отмена",
      previous: "Назад",
      next: "Далее",
      page: "Страница {page}",
      actions: "Действия",
    },
    en: {
      catalog: "Academic catalog",
      courses: "Courses",
      study_groups: "Study groups",
      active: "Active",
      archived: "Archive",
      search: "Search by title",
      loading: "Loading…",
      empty: "No entries",
      denied: "You do not have permission for this operation.",
      failed: "The request failed.",
      conflict: "This entry changed. Refresh the list and try again.",
      retry: "Refresh",
      create: "Create",
      edit: "Edit",
      archive: "Archive",
      restore: "Restore",
      archiveQuestion: "Archive “{title}”?",
      title: "Title",
      description: "Description",
      save: "Save",
      cancel: "Cancel",
      previous: "Previous",
      next: "Next",
      page: "Page {page}",
      actions: "Actions",
    },
  },
});
const route = useRoute();
const organization = computed(() => String(route.params.organizationId ?? ""));
const kind = ref<"courses" | "study_groups">("courses");
const archived = ref(false);
const canRestore = ref(false);
const query = ref("");
const page = ref(1);
const items = ref<CatalogItem[]>([]);
const total = ref(0);
const loading = ref(false);
const saving = ref(false);
const error = ref("");
const editing = ref<CatalogItem | null | undefined>();
const pendingArchive = ref<CatalogItem>();
const title = ref("");
let creationKey = "";
const description = ref("");
const endpoint = computed(
  () =>
    `/api/v1/organizations/${encodeURIComponent(organization.value)}/academic/${kind.value}`,
);
let readGeneration = 0;
let scopeGeneration = 0;
let controller: AbortController | undefined;

function message(status: number) {
  if (status === 404 || status === 401 || status === 403) return "denied";
  return status === 409 ? "conflict" : "failed";
}

async function load() {
  controller?.abort();
  controller = new AbortController();
  const generation = ++readGeneration;
  items.value = [];
  total.value = 0;
  canRestore.value = false;
  error.value = "";
  loading.value = true;
  const params = new URLSearchParams({
    archived: String(archived.value),
    query: query.value,
    page: String(page.value),
  });
  try {
    const response = await fetch(`${endpoint.value}?${params}`, {
      signal: controller.signal,
    });
    if (generation !== readGeneration) return;
    if (!response.ok) {
      error.value = message(response.status);
      return;
    }
    const data = (await response.json()) as CatalogPage;
    if (generation !== readGeneration) return;
    items.value = data.items;
    total.value = data.total;
    canRestore.value = data.can_restore;
  } catch {
    if (generation === readGeneration) error.value = "failed";
  } finally {
    if (generation === readGeneration) loading.value = false;
  }
}

watch(
  [organization, kind, archived],
  () => {
    scopeGeneration++;
    editing.value = undefined;
    pendingArchive.value = undefined;
    title.value = "";
    description.value = "";
    saving.value = false;
  },
  { flush: "sync" },
);
watch(
  [organization, kind, archived, query],
  () => {
    page.value = 1;
  },
  { flush: "sync" },
);
watch([organization, kind, archived, query, page], () => void load(), {
  immediate: true,
  flush: "sync",
});

function edit(item: CatalogItem | null) {
  creationKey = item === null ? crypto.randomUUID() : "";
  pendingArchive.value = undefined;
  editing.value = item;
  title.value = item?.title ?? "";
  description.value = item?.description ?? "";
}

async function mutate(item?: CatalogItem, restore = false) {
  const generation = scopeGeneration;
  const base = endpoint.value;
  const current = editing.value;
  const action = item
    ? restore
      ? "restore"
      : "archive"
    : current
      ? "edit"
      : "create";
  const target = item ?? current;
  const url = target ? `${base}/${target.id}${item ? `/${action}` : ""}` : base;
  const body = item
    ? { version: item.version }
    : {
        title: title.value,
        description: description.value || null,
        ...(current ? { version: current.version } : {}),
      };
  saving.value = true;
  error.value = "";
  try {
    const csrf = await fetch("/api/v1/auth/csrf", {
      headers: { "X-Veriq-CSRF-Bootstrap": "1" },
    });
    if (generation !== scopeGeneration) return;
    if (!csrf.ok) {
      error.value = message(csrf.status);
      return;
    }
    const { csrf_token } = (await csrf.json()) as { csrf_token: string };
    if (generation !== scopeGeneration) return;
    const response = await fetch(url, {
      method: action === "edit" ? "PATCH" : "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf_token,
        ...(action === "create" ? { "Idempotency-Key": creationKey } : {}),
      },
      body: JSON.stringify(body),
    });
    if (generation !== scopeGeneration) return;
    if (!response.ok) {
      error.value = message(response.status);
      return;
    }
    editing.value = undefined;
    pendingArchive.value = undefined;
    await load();
  } catch {
    if (generation === scopeGeneration) error.value = "failed";
  } finally {
    if (generation === scopeGeneration) saving.value = false;
  }
}
</script>

<template>
  <section class="space-y-5">
    <h1 class="text-2xl font-semibold">{{ t("catalog") }}</h1>
    <div class="flex flex-wrap items-end gap-3">
      <select v-model="kind" class="select" :aria-label="t('catalog')">
        <option value="courses">{{ t("courses") }}</option>
        <option value="study_groups">{{ t("study_groups") }}</option>
      </select>
      <select v-model="archived" class="select" :aria-label="t('archived')">
        <option :value="false">{{ t("active") }}</option>
        <option :value="true">{{ t("archived") }}</option>
      </select>
      <input
        v-model="query"
        class="input"
        :aria-label="t('search')"
        :placeholder="t('search')"
        maxlength="160"
      />
      <button
        v-if="!archived && !error"
        class="btn btn-primary"
        type="button"
        @click="edit(null)"
      >
        {{ t("create") }}
      </button>
    </div>
    <p v-if="loading" role="status">{{ t("loading") }}</p>
    <div v-if="error" role="alert" class="alert alert-error">
      {{ t(error) }}
      <button class="btn btn-sm" type="button" @click="load">
        {{ t("retry") }}
      </button>
    </div>
    <form
      v-if="editing !== undefined"
      class="space-y-3 rounded-box border border-base-300 p-4"
      @submit.prevent="mutate()"
    >
      <label class="grid gap-1">
        {{ t("title") }}
        <input v-model="title" required maxlength="160" class="input w-full" />
      </label>
      <label class="grid gap-1">
        {{ t("description") }}
        <textarea
          v-model="description"
          maxlength="2000"
          class="textarea w-full"
        />
      </label>
      <div class="flex gap-2">
        <button class="btn btn-primary" :disabled="saving" type="submit">
          {{ t("save") }}
        </button>
        <button class="btn" type="button" @click="editing = undefined">
          {{ t("cancel") }}
        </button>
      </div>
    </form>
    <div
      v-if="pendingArchive"
      class="alert"
      role="group"
      :aria-label="t('archive')"
    >
      {{ t("archiveQuestion", { title: pendingArchive.title }) }}
      <button
        class="btn btn-warning"
        :disabled="saving"
        type="button"
        @click="mutate(pendingArchive)"
      >
        {{ t("archive") }}
      </button>
      <button class="btn" type="button" @click="pendingArchive = undefined">
        {{ t("cancel") }}
      </button>
    </div>
    <p v-if="!loading && !error && items.length === 0">{{ t("empty") }}</p>
    <div v-if="items.length" class="overflow-x-auto">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{{ t("title") }}</th>
            <th scope="col">{{ t("description") }}</th>
            <th v-if="!archived || canRestore" scope="col">
              {{ t("actions") }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in items" :key="item.id">
            <th scope="row">{{ item.title }}</th>
            <td>{{ item.description }}</td>
            <td v-if="!archived" class="flex flex-wrap gap-2">
              <button class="btn btn-sm" type="button" @click="edit(item)">
                {{ t("edit") }}
              </button>
              <button
                class="btn btn-sm"
                type="button"
                @click="
                  editing = undefined;
                  pendingArchive = item;
                "
              >
                {{ t("archive") }}
              </button>
            </td>
            <td v-else-if="canRestore">
              <button
                class="btn btn-sm"
                type="button"
                :disabled="saving"
                @click="mutate(item, true)"
              >
                {{ t("restore") }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="page > 1 || total > 20" class="flex items-center gap-2">
      <button
        class="btn btn-sm"
        type="button"
        :disabled="page === 1"
        @click="page--"
      >
        {{ t("previous") }}
      </button>
      <span>{{ t("page", { page }) }}</span>
      <button
        class="btn btn-sm"
        type="button"
        :disabled="page * 20 >= total"
        @click="page++"
      >
        {{ t("next") }}
      </button>
    </div>
  </section>
</template>
