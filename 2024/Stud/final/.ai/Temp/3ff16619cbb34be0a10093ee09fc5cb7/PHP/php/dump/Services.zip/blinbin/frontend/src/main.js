import { createApp, reactive } from 'vue';
import App from './App.vue';
import router from './router/';
import Axios from 'axios';
import './styles/main.css';

const app = createApp(App);

// Set up axios with the base URL for API requests
const apiUrl = process.env.VUE_APP_API_URL || '/';

const axiosInstance = Axios.create({
	baseURL: apiUrl,
	headers: {
		'Accept': 'application/json',
		'Content-Type': 'application/json',
	},
	withCredentials: true,
	timeout: 10000,
});

const authState = reactive({
	isAuthenticated: false,
	user: null,
  });

  
app.provide('authState', authState);
app.provide('$axios', axiosInstance);

app.use(router)
app.mount('#app')
