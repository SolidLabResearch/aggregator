<template>
  <div class="p-6">
    <h1 class="text-xl font-bold mb-4">Registration Result</h1>
    <div v-if="loading">Completing registration...</div>
    <div v-else-if="error" class="text-red-600">{{ error }}</div>
    <div v-else>
      <h2>Endpoints</h2>
      <ul>
        <li v-for="(url, key) in endpoints" :key="key">
          {{ key }}: {{ url }}
        </li>
      </ul>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref, onMounted } from "vue";
import { completeRegistration, RegistrationEndpoints } from "@/api/registration";
import { useRoute } from "vue-router";

export default defineComponent({
  setup() {
    const route = useRoute();
    const endpoints = ref<RegistrationEndpoints>({});
    const error = ref("");
    const loading = ref(true);

    onMounted(async () => {
      const code = route.query.code as string;
      const state = route.query.state as string;
      if (!code || !state) {
        error.value = "Missing code or state in query params";
        loading.value = false;
        return;
      }
      try {
        endpoints.value = await completeRegistration({ code, state });
      } catch (err: any) {
        error.value = err.response?.data || err.message;
      } finally {
        loading.value = false;
      }
    });

    return { endpoints, error, loading };
  },
});
</script>
