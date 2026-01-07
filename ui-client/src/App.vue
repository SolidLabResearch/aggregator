<template>
  <div id="app" class="min-h-screen bg-gray-50">
    <header class="bg-blue-600 text-white p-4 shadow-md">
      <h1 class="text-2xl font-bold">Aggregator Client Registration</h1>
    </header>

    <main class="p-6">
      <router-view />
    </main>

    <footer class="bg-gray-200 text-gray-700 p-4 mt-12 text-center">
      &copy; {{ new Date().getFullYear() }} Aggregator Client
    </footer>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "App",
});
</script>

<style scoped>
/* Optional: basic styling */
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
}
</style>
