import { createRouter, createWebHistory } from "vue-router";
import LoginView from "@/views/LoginView.vue";
import RegistrationView from "@/views/RegistrationView.vue";
import RegistrationCallbackView from "@/views/RegistrationCallbackView.vue";  
import LoginCallbackView from "@/views/LoginCallbackView.vue";

const routes = [
  { path: "/", redirect: "/login" },
  { path: "/login", component: LoginView },
  { path: "/login/callback", component: LoginCallbackView },
  { path: "/register", component: RegistrationView },
  { path: "/register/callback", component: RegistrationCallbackView }
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});
