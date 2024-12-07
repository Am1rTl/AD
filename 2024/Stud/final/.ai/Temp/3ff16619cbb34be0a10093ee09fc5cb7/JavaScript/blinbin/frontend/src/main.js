"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var vue_1 = require("vue");
var App_vue_1 = require("./App.vue");
var router_1 = require("./router/");
var axios_1 = require("axios");
require("./styles/main.css");
var app = vue_1.createApp(App_vue_1.default);
// Set up axios with the base URL for API requests
var apiUrl = process.env.VUE_APP_API_URL || '/';
var axiosInstance = axios_1.default.create({
    baseURL: apiUrl,
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    },
    withCredentials: true,
    timeout: 10000,
});
var authState = vue_1.reactive({
    isAuthenticated: false,
    user: null,
});
app.provide('authState', authState);
app.provide('$axios', axiosInstance);
app.use(router_1.default);
app.mount('#app');
//# sourceMappingURL=main.js.map