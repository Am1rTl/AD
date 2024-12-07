<template>
  <nav class="bg-black text-white p-4 border-b border-white">
    <div class="flex justify-between items-center">
      <router-link to="/" class="text-xl font-bold">BlinBin</router-link>
      
        <div class="flex space-x-6">
        <template v-for="(link, index) in navigationLinks" :key="index">
          <router-link :to="link.path" class="hover:text-gray-300">{{ link.label }}</router-link>
        </template>
      </div>
      
      <!-- Authenticated User Links -->
      <div v-if="authState.isAuthenticated" class="space-x-4">
        <button @click="logout" class="hover:text-gray-300">Logout</button>
        <router-link to="/user/me" class="hover:text-gray-300">Profile</router-link>
      </div>

      <!-- Guest Links -->
      <div v-else class="space-x-4">
        <router-link to="/login" class="hover:text-gray-300">Log In</router-link>
        <router-link to="/signup" class="hover:text-gray-300">Sign Up</router-link>
      </div>
    </div>
  </nav>
</template>

<script setup>
  import {inject} from 'vue';

  const axios = inject('$axios');
  
  import { getNavigationLinks } from '../router/index.js';
  const navigationLinks =  getNavigationLinks() 

  const authState = inject('authState');

  function logout() {
    authState.isAuthenticated = false;
    authState.user = null;
    axios.post('/api/auth/logout');
  }
</script>

<style scoped>
</style>
