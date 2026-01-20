<template>
  <div class="p-6">
    <h1 class="text-xl font-bold">Logging you in...</h1>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "vue";
import { exchangeCodeForToken } from "@/api/auth";
import { useRouter } from "vue-router";

export default defineComponent({
  setup() {
    const router = useRouter();

    onMounted(async () => {
      try {
        const idToken = await exchangeCodeForToken();
        localStorage.setItem("id_token", idToken); // store for registration
        router.push("/register");
      } catch (err: any) {
        alert("Login failed: " + err.message);
      }
    });
  },
});
</script>

