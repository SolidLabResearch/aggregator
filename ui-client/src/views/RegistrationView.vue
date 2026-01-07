<template>
  <div class="p-6">
    <h1 class="text-xl font-bold mb-4">Register</h1>
    <RegistrationForm @registered="onRegistered"/>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import RegistrationForm from "@/components/RegistrationForm.vue";

export default defineComponent({
  components: { RegistrationForm },
  setup() {
    const onRegistered = (redirectUrl: string) => {
      // redirect to Keycloak login
      window.location.href = redirectUrl;
    };
    return { onRegistered };
  },
});
</script>
