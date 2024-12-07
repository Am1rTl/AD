<template>
  <div class="min-h-screen text-white flex justify-center items-center">
    <div class="p-8 rounded-lg shadow-lg w-full max-w-sm">
      <h2 class="text-2xl mb-6 text-center">Login</h2>
      <form @submit.prevent="handleSubmit">
        <div class="mb-4">
          <label for="name" class="block text-sm">Name</label>
          <input type="text" id="login-form-login-input" v-model="formData.name" placeholder="Enter your name"
                 class="w-full p-2 mt-2 rounded text-white bg-[#3d3d3d]" />
        </div>
        <div class="mb-6">
          <label for="password" class="block text-sm">Password</label>
          <input type="password" id="login-form-password-input" v-model="formData.password"
                 placeholder="Enter your password" class="w-full p-2 mt-2 rounded text-white bg-[#3d3d3d]" />
        </div>
        <button id="login-button"  type="submit" class="w-full py-2 bg-[#3d3d3d] rounded text-white hover:bg-blue-400">
          Login
        </button>

        <!-- Message Display -->
        <p v-if="errorMessage" class="mt-4 text-red-500">{{ errorMessage }}</p>
      </form>
    </div>
  </div>
</template>

<script setup>
import {inject, ref } from 'vue';
import { useRouter } from 'vue-router';

const router = useRouter();
const axios = inject('$axios');

const authState = inject('authState');

const formData = {
  name: '',
  password: ''
};

const errorMessage = ref(null);

async function handleSubmit() {
  try {
    const response = await axios.post('/api/auth/login', formData);
    
    authState.isAuthenticated = true;
    // console.log(response.data.data)
    authState.user = response.data.data;

    // Set the cookie in the browser
    document.cookie = `session=${response.data.session}; path=/`;

    router.push('/home');
  } catch (error) {
    errorMessage.value = error.response.data.message || 'An error occurred.';
  }
}
</script>

<style scoped>
/* Optional styling */
</style>