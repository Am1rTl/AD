import { createRouter, createWebHistory } from 'vue-router';
import HomePage from '@/pages/HomePage.vue';
import LoginPage from '@/pages/LoginPage.vue';
import SignUpPage from '@/pages/SignUpPage.vue';
import AddPostPage from '@/pages/AddPostPage.vue';
import UsersPage from '@/pages/UsersPage.vue'
import HallOfRespect from '@/pages/HallOfRespect.vue';
import Tos from '@/pages/Tos.vue';
import UserProfile from '@/pages/UserProfile.vue';
import ViewPostPage from '@/pages/ViewPostPage.vue';

const routes = [
    {
        path: '/',
        component: HomePage,
        name: 'Home',
        navigationBarCenter: true,
        meta: {
            "title": "Home"
        }
    },
    {
        path: '/login',
        component: LoginPage,
        name: 'Login',
        navigationBarCenter: false,
        meta: {
            "title": "Log in"
        }
    },
    {
        path: '/signup',
        component: SignUpPage,
        name: 'Sign Up',
        navigationBarCenter: false,
        meta: {
            "title": "Sign up"
        }
    },
    {
        path: '/addpost',
        component: AddPostPage,
        name: 'Add Post',
        navigationBarCenter: true,
        meta: {
            "title": "Add post"
        }

    },
    {
        path: '/post/:postId',
        component: ViewPostPage,
        name: 'View Post',
        navigationBarCenter: false,

    },
    {
        path: '/users',
        component: UsersPage,
        name: 'Users',
        navigationBarCenter: true,
        meta: {
            "title": "Users"
        }
    },
    {
        path: '/user/:userId',
        component: UserProfile,
        name: 'User Profile',
        navigationBarCenter: false,
    },
    {
        path: '/hor',
        navigationBarCenter: true,
        name: 'Hall of Respect',
        component: HallOfRespect,
        meta: {
            "title": "Hall of Respect"
        }
    },
    {
        path: '/tos',
        navigationBarCenter: true,
        component: Tos,
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

const redirectRoute = { path: '/home', redirect: '/' };

const router = createRouter({
    history: createWebHistory(),
    routes: [...routes, redirectRoute]
});

router.afterEach(to => {
    if (to?.meta?.title) {
        document.title = `${to.meta.title} — BlinBin`;
    } else {
        document.title = 'BlinBin';
    }
});

router.beforeEach((to, from, next) => {
    if (to.path === '/telegram') {
        window.location.href = 'https://t.me/mctfnews';
    } else {
        next();
    }
});

export const getNavigationLinks = () => {
    return routes.filter((route) => route.navigationBarCenter).map((route) => ({
        path: route.path,
        label: route.meta ? route.meta.title : '',
    }));
};


export default router;
