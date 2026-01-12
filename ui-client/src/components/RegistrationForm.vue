<template>
  <form @submit.prevent="submit" class="space-y-4 p-4 max-w-md">
    <div>
      <label class="block mb-1 font-semibold">IDP Provider URL:</label>
      <input
        v-model="idpProvider"
        class="border p-2 w-full"
        placeholder="Enter your IDP Provider URL"
      />
    </div>

    <div>
      <label class="block mb-1 font-semibold">Authorization Server URL (as_url):</label>
      <input
        v-model="asUrl"
        class="border p-2 w-full"
        placeholder="Enter your AS URL"
      />
    </div>

    <button type="submit" class="bg-blue-500 text-white px-4 py-2 rounded">
      Register
    </button>
  </form>
</template>

<script lang="ts">
import { defineComponent, ref } from "vue";
import { startRegistration, fetchAuthUrl, buildRedirectUri } from "@/api/registration";
import { config } from "@/config";

export default defineComponent({
  emits: ["registered"],
  setup(_, { emit }) {
    // Pre-fill the form with default values from config
    const idpProvider = ref(config.keycloak.url);       // default Keycloak URL
    const asUrl = ref(config.asDefaultUrl);       // default Aggregator URL

    const submit = async () => {
      try {
        const res = await startRegistration(idpProvider.value, asUrl.value);
        const authUrl = `${await fetchAuthUrl(idpProvider.value)}`;
        const redirectUrl = buildRedirectUri(authUrl, res);
        emit("registered", redirectUrl);
      } catch (err: any) {
        alert("Registration failed: " + (err.response?.data || err.message));
      }
    };

    return { idpProvider, asUrl, submit };
  },
});
</script>
