<template>
    <PostLayout>
        <!-- Editor Slot -->
        <template #editor>
            <pre id="post-text-editor"  class="editor w-full h-full bg-black text-white p-4 whitespace-pre-wrap">
        {{ post.text }}
      </pre>
        </template>

        <!-- Sidebar Slot -->
        <template #sidebar>
            <div class="bg-[#181818] p-4 rounded mb-4">
                <p><strong>Title:</strong> {{ post.title }}</p>
                <p><strong>Author:</strong> {{ post.author.name }}</p>
                <p><strong>Visibility:</strong> {{ post.private ? 'Private' : 'Public' }}</p>
                <p><strong>Created At:</strong> {{ humanReadableDate(post.created_at) }}</p>
            </div>

            <!-- Comment Form -->
            <form @submit.prevent="addComment">
                <div class="bg-[#181818] p-4 rounded mb-2">
                    <label for="comment-text" class="text-gray-300">Add a comment:</label>
                    <textarea id="comment-text" v-model="newComment.text" class="w-full bg-black text-white p-2 rounded mt-2" required></textarea>
                </div>
                <button type="submit" class="bg-blue-500 text-white px-4 py-2 rounded">Submit Comment</button>
            </form>

            <h2 class="text-lg font-bold mb-4">Comments</h2>
            <div class="space-y-4 w-full">
                <div v-for="comment in post.comments" :key="comment.id" class="bg-[#181818] text-gray-300 p-4 rounded">
                    <p class="font-semibold text-white">{{ comment.author.name }}</p>
                    <p>{{ comment.text }}</p>
                    <p class="text-sm text-gray-500">{{ comment.date }}</p>
                </div>
            </div>

        </template>
    </PostLayout>
</template>

<script setup>
import { ref, onMounted, inject } from 'vue';
import PostLayout from '@/components/PostLayout.vue';
import { useRoute } from 'vue-router';

const route = useRoute();
const axios = inject('$axios');

const postId = route.params.postId; // Assuming the ID is passed as a route parameter

const post = ref({ text: '', comments: [], author: {} });
const newComment = ref({ text: '' }); // Reactive state for new comment text

onMounted(async () => {
    try {
        const response = await axios.get(`/api/posts/${postId}`);
        post.value = response.data.data;

        // Fetch comments for the post
        const commentResponse = await axios.get(`/api/posts/${postId}/comments`);
        if (commentResponse.status === 200) {
            post.value.comments = commentResponse.data.data;
        }
    } catch (error) {
        console.error('Error fetching post data:', error);
    }
});

function humanReadableDate(dateStr) {
    if (!dateStr) return 'N/A'; // Handle null or undefined dates

    const date = new Date(dateStr);
    const options = { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false };
    return date.toLocaleDateString('en-US', options);
}

async function addComment() {
    try {
        const response = await axios.post(`/api/posts/${postId}/comments`, { text: newComment.value.text });
        if (response.status === 201) {
            post.value.comments.push(response.data.data); // Add the new comment to the post's comments list
            newComment.value.text = ''; // Clear the form after submission
        }
    } catch (error) {
        console.error('Error adding comment:', error);
    }
}
</script>

<style scoped>
/* You can add your styles here */
</style>