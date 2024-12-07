<template>
  <div id="app">
    <Navbar />
    <router-view @user-authenticated="setAuthenticated" @user-logged-out="setLoggedOut" />
  </div>
</template>

<script>
import Navbar from "@/components/Navbar.vue";

export default {
  name: 'App',
  components: {
    Navbar,
  }
}
</script>

<style>
:root { --background: #060606; }
body { background-color: var(--background); }
</style>