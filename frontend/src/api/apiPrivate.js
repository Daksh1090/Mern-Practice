import axios from "axios";
import authApi from "./authApi";

const BASE_URL = "http://localhost:5000";

let accessToken = null;
export const setAccessToken = (token) => (accessToken = token);

const apiPrivate = axios.create({
  baseURL: BASE_URL,
  withCredentials: true,
});

apiPrivate.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

apiPrivate.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config;

    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;

      const res = await authApi.post("/api/auth/refresh");
      setAccessToken(res.data.accessToken);

      original.headers.Authorization = `Bearer ${res.data.accessToken}`;
      return apiPrivate(original);
    }

    return Promise.reject(error);
  }
);

export default apiPrivate;
