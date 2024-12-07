<template>
  <div class="min-h-screen text-white flex flex-col items-center py-10">
    <div class="mb-8 bg-white">
      <img src="@/assets/blinbin.svg" alt="Logo" class="w-64 h-64">
    </div>
    <table v-if="posts.length > 0">
      <thead>
        <tr>
          <th class="px-4 py-2">Title</th>
          <th class="px-4 py-2">Comments</th>
          <th class="px-4 py-2">Created By</th>
          <th class="px-4 py-2">Added</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="post in posts" :key="post.id">
          <td class="px-4 py-2 underline">
            <router-link :to="{ name: 'View Post', params: { postId: post.id } }">
              {{ post.title }}
            </router-link>
          </td>
          <td class="px-4 py-2">{{ post.comment_count || "-" }}</td>
          <td class="px-4 py-2 underline">
            <router-link :to="{ name: 'User Profile', params: { userId: post.author.id } }">
              {{ post.author.name }}
            </router-link>
          </td>
          <td class="px-4 py-2">{{ humanReadableDate(post.created_at) }}</td>
        </tr>
      </tbody>
    </table>
    <div v-else class="text-center mt-10">
      <p>No posts available.</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, inject } from 'vue';
const axios = inject('$axios');

// Declare posts array
const posts = ref([]);

// Fetch data on component mount
onMounted(async () => {
  try {
    const response = await axios.get('/api/posts/');
    posts.value = response.data.data;
  } catch (error) {
    console.error('Error fetching posts:', error);
  }
});

function humanReadableDate(dateStr) {
  if (!dateStr) return 'N/A'; // Handle null or undefined dates

  const date = new Date(dateStr);
  const options = { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false };
  return date.toLocaleDateString('en-US', options);
}
</script>
<style scoped>
/* table tr:nth-child(even) {
  background-color: #060606;
} */
</style>