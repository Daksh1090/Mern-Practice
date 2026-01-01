import axios from "axios";

const BASE_URL = "http://localhost:5000";


const authApi = axios.create({
  baseURL: BASE_URL,
  withCredentials: true,
});

export default authApi;