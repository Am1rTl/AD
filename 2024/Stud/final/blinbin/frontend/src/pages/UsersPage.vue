<template>
  <div class="min-h-screen text-white flex flex-col items-center py-10">
    <div class="mb-8">
      <!-- <img src="@/assets/blinbin.svg" alt="Logo" class="w-64 h-64"> -->
    </div>
    <table class="bg-[#3d3d3d]">
      <thead>
        <tr>
          <th class="px-4 py-2">User ID</th>
          <th class="px-4 py-2">Username</th>
          <th class="px-4 py-2">Pastes</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="user in users" :key="user.id">
          <td class="px-4 py-2">{{ user.id }}</td>
          <td class="px-4 py-2 underline">
            <router-link
              :to="{ name: 'User Profile', params: { userId: user.id } }"
              @click.prevent="addUnderscore(user.name)"
            >
              {{ formattedUsername(user.name) }}
            </router-link>
          </td>
          <td class="px-4 py-2">{{ user.posts_count || '-' }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
import { ref, onMounted, inject } from 'vue';
const axios = inject('$axios');

// Declare users array
const users = ref([]);

// Fetch data on component mount
onMounted(async () => {
  try {
    const response = await axios.get('/api/users/');
    users.value = response.data.data;
  } catch (error) {
    console.error('Error fetching users:', error.response.data.message || "unknown");
  }
});

// Function to add an underscore to a username
const addUnderscore = (username) => {
  return username.split('').join('_');
};

// Computed property to format the username without underscores and underline it
const formattedUsername = (username) => {
  return username;
};
</script>

<style scoped>
.underline {
  text-decoration: underline;
}
</style>