"use strict";
var __spreadArray = (this && this.__spreadArray) || function (to, from) {
    for (var i = 0, il = from.length, j = to.length; i < il; i++, j++)
        to[j] = from[i];
    return to;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getNavigationLinks = void 0;
var vue_router_1 = require("vue-router");
var HomePage_vue_1 = require("@/pages/HomePage.vue");
var LoginPage_vue_1 = require("@/pages/LoginPage.vue");
var SignUpPage_vue_1 = require("@/pages/SignUpPage.vue");
var AddPostPage_vue_1 = require("@/pages/AddPostPage.vue");
var UsersPage_vue_1 = require("@/pages/UsersPage.vue");
var HallOfRespect_vue_1 = require("@/pages/HallOfRespect.vue");
var Tos_vue_1 = require("@/pages/Tos.vue");
var UserProfile_vue_1 = require("@/pages/UserProfile.vue");
var ViewPostPage_vue_1 = require("@/pages/ViewPostPage.vue");
var routes = [
    {
        path: '/',
        component: HomePage_vue_1.default,
        name: 'Home',
        navigationBarCenter: true,
        meta: {
            "title": "Home"
        }
    },
    {
        path: '/login',
        component: LoginPage_vue_1.default,
        name: 'Login',
        navigationBarCenter: false,
        meta: {
            "title": "Log in"
        }
    },
    {
        path: '/signup',
        component: SignUpPage_vue_1.default,
        name: 'Sign Up',
        navigationBarCenter: false,
        meta: {
            "title": "Sign up"
        }
    },
    {
        path: '/addpost',
        component: AddPostPage_vue_1.default,
        name: 'Add Post',
        navigationBarCenter: true,
        meta: {
            "title": "Add post"
        }
    },
    {
        path: '/post/:postId',
        component: ViewPostPage_vue_1.default,
        name: 'View Post',
        navigationBarCenter: false,
    },
    {
        path: '/users',
        component: UsersPage_vue_1.default,
        name: 'Users',
        navigationBarCenter: true,
        meta: {
            "title": "Users"
        }
    },
    {
        path: '/user/:userId',
        component: UserProfile_vue_1.default,
        name: 'User Profile',
        navigationBarCenter: false,
    },
    {
        path: '/hor',
        navigationBarCenter: true,
        name: 'Hall of Respect',
        component: HallOfRespect_vue_1.default,
        meta: {
            "title": "Hall of Respect"
        }
    },
    {
        path: '/tos',
        navigationBarCenter: true,
        component: Tos_vue_1.default,
        meta: {
            "title": "TOS"
        }
    },
    {
        path: '/telegram',
        navigationBarCenter: true,
        meta: {
            "title": "TG"
        }
    },
];
var redirectRoute = { path: '/home', redirect: '/' };
var router = vue_router_1.createRouter({
    history: vue_router_1.createWebHistory(),
    routes: __spreadArray(__spreadArray([], routes), [redirectRoute])
});
router.afterEach(function (to) {
    var _a;
    if ((_a = to === null || to === void 0 ? void 0 : to.meta) === null || _a === void 0 ? void 0 : _a.title) {
        document.title = to.meta.title + " \u2014 BlinBin";
    }
    else {
        document.title = 'BlinBin';
    }
});
router.beforeEach(function (to, from, next) {
    if (to.path === '/telegram') {
        window.location.href = 'https://t.me/mctfnews';
    }
    else {
        next();
    }
});
var getNavigationLinks = function () {
    return routes.filter(function (route) { return route.navigationBarCenter; }).map(function (route) { return ({
        path: route.path,
        label: route.meta ? route.meta.title : '',
    }); });
};
exports.getNavigationLinks = getNavigationLinks;
exports.default = router;
//# sourceMappingURL=index.js.map