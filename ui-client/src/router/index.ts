import { createRouter, createWebHistory } from "vue-router";
import RegistrationView from "@/views/RegistrationView.vue";
import RegistrationCallbackView from "@/views/RegistrationCallbackView.vue";

const routes = [
  { path: "/", component: RegistrationView },
  { path: "/callback", component: RegistrationCallbackView },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});
