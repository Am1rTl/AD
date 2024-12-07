"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var axios_1 = require("axios");
var API_URL = 'http://localhost:3000/api';
var client = axios_1.default.create({
    baseURL: API_URL,
});
client.interceptors.request.use(function (config) {
    var token = localStorage.getItem('token');
    if (token) {
        config.headers.Authorization = "Bearer " + token;
    }
    return config;
});
exports.default = client;
//# sourceMappingURL=client.js.map