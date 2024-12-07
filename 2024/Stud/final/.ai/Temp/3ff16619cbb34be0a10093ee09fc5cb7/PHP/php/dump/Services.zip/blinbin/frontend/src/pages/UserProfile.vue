<template>
  <div class="min-h-screen text-white flex flex-col items-center py-10">
    <!-- User Profile Section -->
    <div class="mb-8 bg-white p-4">
      <h1 class="text-2xl font-bold text-black">{{ user.name }}</h1>
    </div>
    <!-- Display count of posts for user -->
    <div v-if="user.posts_count">
      <p>Number of posts: {{ user.posts_count }}</p>
    </div>
    <div v-else>
      <p>No posts that u can see</p>
    </div>

    <!-- Display referenced posts of this user-->
    <h2 class="text-lg font-bold mb-4 mt-8">References</h2>
    <div v-if="user.references.length">
      <div  class="flex flex-row flex-wrap   space-around items-stretch space-between justify-center space-x-4">
        <div
          v-for="(reference, index) in user.references"
          :key="reference.id"
          class="bg-[#181818] text-gray-300 p-4 mt-4 mb-4 rounded w-full max-w-sm card"
          :class="{ 'mr-64': (index + 1) % 2 === 0 , 'bg-green-500': reference.visibility, 'bg-red-500': !reference.visibility }"
        >
          <p class="font-semibold text-white">{{ reference.author.name }}</p>
          <p>Title: {{ reference.post.title }}</p>
          <p>Visibility: {{ reference.visibility ? 'Public' : 'Private' }}</p>
        </div>
      </div>
    </div>
    <div v-else class="text-center text-gray-400">No references yet.</div>

    <!-- Posts Section -->
    <div class="w-full max-w-4xl mb-10">
      <h2 class="text-lg font-semibold">Posts</h2>
      <table v-if="user.posts.length">
        <thead>
          <tr>
            <th class="px-4 py-2">Title</th>
            <th class="px-4 py-2">Comments</th>
            <th class="px-4 py-2">Added</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="post in user.posts" :key="post.id">
          <td class="px-4 py-2 underline">
            <router-link :to="{ name: 'View Post', params: { postId: post.id } }">
              {{ post.title }}
            </router-link>
          </td>
            <td class="px-4 py-2">{{ post.comment_count || "-"}}</td>
            <td class="px-4 py-2">{{ humanReadableDate(post.created_at) }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="text-center text-gray-400">No posts yet.</div>
    </div>

    <!-- Comment Form -->
    <form @submit.prevent="submitComment" class="mt-10 w-full max-w-4xl bg-[#3d3d3d] p-6 rounded-lg shadow-md">
      <textarea v-model="newCommentText" placeholder="Write a comment..." rows="3" required class="w-full px-4 py-2 border border-gray-500 rounded mb-4 bg-black text-white"></textarea>
      <button type="submit" class="bg-[#181818] px-4 py-2 rounded hover:bg-blue-700">Submit Comment</button>
    </form>

    <!-- Profile Comments Section -->
    <h2 class="text-lg font-bold mb-4 mt-8">Comments</h2>
    <div class="space-y-4 w-full">
      <div v-for="comment in user.profileComments" :key="comment.id" class="bg-[#181818] text-gray-300 p-4 rounded">
        <p class="font-semibold text-white">{{ comment.author.name }}</p>
        <p>{{ comment.text }}</p>
      </div>
    </div>

  </div>
</template>

<script setup>
import { ref, onMounted, inject } from 'vue';
import { useRoute, useRouter } from 'vue-router';

const router = useRouter();
const route = useRoute();
const axios = inject('$axios');

// Declare user object
const user = ref({ id: null, name: '', posts: [], profileComments: [], references: [] });
const newCommentText = ref('');

onMounted(async () => {
  var userId = route.params.userId;

  // Construct the API path based on whether it's the current user or another user
  var path;
  if (userId === 'me') {
    path = `/api/users/me`;
  } else if (!isNaN(userId)) {
    path = `/api/users/${userId}`;
  } else {
    router.push('/404'); // Redirect to 404 if invalid userId
    return;
  }

  try {
    const responseUser = await axios.get(path);
    user.value = { ...responseUser.data.data, profileComments: [], references: [] };
    userId = user.value.id;

    // Fetch the posts of the user
    // const responsePosts = await axios.get(`/api/users/${userId}/posts`);
    // user.value.posts = responsePosts.data.data;

    // Fetch the comments of the user
    const responseComments = await axios.get(`/api/users/${userId}/comments`);
    user.value.profileComments = responseComments.data.data;

    // Fetch references and visibility statuses
    const responseReferences = await axios.get(`/api/users/${userId}/references`);
    const refs = responseReferences.data.data;
    for (let reference of refs) {
      if (reference.post && reference.post.id) {
        const postPath = `/api/posts/`+reference.post.title+`/accessible`;
        try {
          const visibilityResponse = await axios.post(postPath, { private: false });
          console.log(visibilityResponse.data.data.status);
          reference.visibility = visibilityResponse.data.data.status;
        } catch (error) {
          console.error('Error fetching visibility status for post:', error);
        }
      }
    }

    user.value.references = refs;

  } catch (error) {
    console.error('Error fetching user details:', error);
  }
});

function humanReadableDate(dateStr) {
  if (!dateStr) return 'N/A'; // Handle null or undefined dates

  const date = new Date(dateStr);
  const options = { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false };
  return date.toLocaleDateString('en-US', options);
}

async function submitComment() {
  try {
    const userId = user.value.id;
    const response = await axios.post(`/api/users/${userId}/comments`, {
      text: newCommentText.value
    });

    // Add the new comment to the existing comments list
    user.value.profileComments.push({
      id: response.data.data.id,
      author: {
        id: response.data.data.author.id,
        name: response.data.data.author.name
      },
      text: newCommentText.value
    });

    // Clear the comment input field
    newCommentText.value = '';

    console.log('Comment submitted successfully:', response.data.message);
  } catch (error) {
    console.error('Error submitting comment:', error);
  }
}
</script>

<style scoped>
.card:nth-child(6n) {
  margin-top: 24px;
}

/* Ensure vertical alignment */
.items-stretch {
  align-items: stretch;
}
/* Add your styles here */
</style>