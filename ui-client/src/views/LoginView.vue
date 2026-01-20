<template>
  <div class="p-6">
    <h1 class="text-xl font-bold mb-4">Login</h1>
    <button @click="login" class="bg-blue-500 text-white px-4 py-2 rounded">
      Login with Keycloak
    </button>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import { buildLoginUrl } from "@/api/auth";

export default defineComponent({
  setup() {
    const login = async () => {
      const url = await buildLoginUrl();
      window.location.href = url;
    };

    return { login };
  },
});
</script>
