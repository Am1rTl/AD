<template>
  <PostLayout>
    <!-- Editor Slot -->
    <template #editor>
      <textarea v-model="pasteContent" class="editor mousetrap w-full h-full resize-none outline-none bg-black text-white" wrap="off" placeholder="READ OUR TERMS OF SERVICE BEFORE CREATING A POST..."></textarea>
    </template>

    <!-- Sidebar Slot -->
    <template #sidebar>
      <input v-model="title" name="title" id="title" type="text" class="bg-[#3d3d3d] text-white w-full py-1 mb-2 px-2 rounded outline-none" placeholder="Title (no special characters)" @input="sanitizeTitle">
      
      <label>
        <input v-model="isPrivate" type="checkbox" class="mr-2"> Is Private
      </label>

      <button @click="createPost" class="bg-[#3d3d3d] text-white w-full py-2 mb-2 hover:bg-gray-600 rounded">
        Create
      </button>
      <button @click="clearText" class="bg-[#3d3d3d] text-white w-full py-2 hover:bg-gray-600 rounded">
        Clear
      </button>
    </template>
  </PostLayout>
</template>

<script setup>
import { ref, inject } from 'vue';
import PostLayout from '@/components/PostLayout.vue'; // Import the layout component

const axios = inject('$axios');

const pasteContent = ref('');
const title = ref('');
const isPrivate = ref(false);

function sanitizeTitle() {
  title.value = title.value.replace(/[^\w\s]/gi, '');
}

function createPost() {
  if (!pasteContent.value.trim()) {
    alert('Please enter some content before creating a post.');
    return;
  }

  axios.post('/api/posts', { title: title.value, text: pasteContent.value, private: isPrivate.value })
    .then(response => {
      console.log('Post created successfully:', response.data);
      clearText();
      alert('Post created successfully!');
    })
    .catch(error => {
      console.error('Error creating post:', error);
      alert('An error occurred while creating the post. Please try again.');
    });
}

function clearText() {
  pasteContent.value = '';
  title.value = '';
}
</script>
