import axios from "axios";

const API_BASE_URL = "http://127.0.0.1:8000";

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("access_token");

    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      console.warn(
        "[ThreatLens] Authentication failed:",
        error.config?.url
      );

      localStorage.removeItem("access_token");
      localStorage.removeItem("token_type");

      window.dispatchEvent(
        new Event("auth:unauthorized")
      );
    }

    return Promise.reject(error);
  }
);

export default apiClient;