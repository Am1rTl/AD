<template>
  <div class="min-h-screen text-white flex justify-center items-center">
    <div class="p-8 rounded-lg shadow-lg w-full max-w-sm">
      <h2 class="text-2xl mb-6 text-center">Sign Up</h2>
      <form @submit.prevent="handleSubmit">
        <div class="mb-4">
          <label for="name" class="block text-sm">Name</label>
          <input type="text" id="name" v-model="formData.name" placeholder="Enter your name"
                 class="w-full p-2 mt-2 rounded text-white bg-[#3d3d3d]" />
        </div>
        <div class="mb-4">
          <label for="password" class="block text-sm">Password</label>
          <input type="password" id="password" v-model="formData.password"
                 placeholder="Enter your password" class="w-full p-2 mt-2 rounded text-white bg-[#3d3d3d]" />
        </div>
        <div class="mb-4">
          <label for="confirm_password" class="block text-sm">Confirm Password</label>
          <input type="password" id="confirm_password" v-model="formData.confirmPassword"
                 placeholder="Confirm your password" class="w-full p-2 mt-2 rounded text-white bg-[#3d3d3d]" />
        </div>
        <button type="submit" class="w-full py-2 bg-[#3d3d3d] rounded text-white hover:bg-blue-400">
          Sign Up
        </button>
      </form>

      <!-- Message Display -->
      <p v-if="errorMessage" class="mt-4 text-red-500">{{ errorMessage }}</p>
      <p v-if="successMessage" class="mt-4 text-green-500">{{ successMessage }}</p>

    </div>
  </div>
</template>

<script setup>
import { inject, ref } from 'vue';
const axios = inject('$axios');

const formData = {
  name: '',
  password: '',
  confirmPassword: ''
};

const errorMessage = ref(null);
const successMessage = ref(null);

async function handleSubmit() {
  if (formData.password !== formData.confirmPassword) {
    errorMessage.value = 'Passwords do not match!';
    return;
  }

  try {
    // Remove confirmPassword field
    delete formData.confirmPassword;

    const response = await axios.post('/api/auth/signup', formData);
    if (response.status === 201) {
      errorMessage.value = null; // Clear error message
      successMessage.value = 'Sign up successful! Redirecting to login page...';
      setTimeout(() => {
        window.location.href = '/login';
      }, 1000);
    }
  } catch (error) {
    errorMessage.value = error.response.data.message || 'An error occurred.';
    successMessage.value = null; // Clear success message 
  }
}
</script>

<style scoped>
/* Optional styling */
</style>