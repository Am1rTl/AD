<template>
    <div class="min-h-screen flex text-white">
      <!-- Left Section -->
      <div class="flex-grow p-4">
        <slot name="editor"></slot>
      </div>
  
      <!-- Right Sidebar -->
      <div class="w-64 p-4 flex flex-col items-center">
        <div class="mb-4 bg-white">
          <img src="@/assets/blinbin.svg" alt="Logo" class="w-32 h-32 mx-auto" />
        </div>
        <slot name="sidebar"></slot>

      <p class="mt-8 text-sm text-gray-400 text-center">
        Please note that all posted information is publicly available and must follow our
        <a href="/tos" class="underline">TOS</a>.
      </p>
      </div>
    </div>
  </template>
  
  <script setup>
  // No specific logic for this reusable component
  </script>
  
  <style scoped>
  </style>
  