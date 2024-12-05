"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logout = exports.checkAuth = void 0;
var checkAuth = function () {
    var cookies = document.cookie.split(';');
    var connectSid = cookies.find(function (cookie) { return cookie.trim().startsWith('connect.sid='); });
    return !!connectSid;
};
exports.checkAuth = checkAuth;
var logout = function () {
    document.cookie = "connect.sid=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
};
exports.logout = logout;
//# sourceMappingURL=helpers.js.map