import axios from "axios";

// ========================
// 🍪 COOKIE HELPERS
// ========================

export const setCookie = (name, value, days = 7) => {
  try {
    const date = new Date();
    date.setTime(date.getTime() + days * 24 * 60 * 60 * 1000);
    const expires = date.toUTCString();
    const cookieString = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; SameSite=Lax`;
    document.cookie = cookieString;
    console.log(`[✅ COOKIE] Set ${name}`);
  } catch (err) {
    console.error("[❌ COOKIE] Error setting cookie:", err);
  }
};

export const getCookie = (name) => {
  try {
    const nameEQ = name + "=";
    const cookies = document.cookie.split(";");
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.indexOf(nameEQ) === 0) {
        const value = decodeURIComponent(cookie.substring(nameEQ.length));
        console.log(`[🔍 COOKIE] Found ${name} in cookies`);
        return value;
      }
    }
  } catch (err) {
    console.error("[❌ COOKIE] Error getting cookie:", err);
  }
  return null;
};

export const deleteCookie = (name) => {
  try {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
    console.log(`[🗑️ COOKIE] Deleted ${name}`);
  } catch (err) {
    console.error("[❌ COOKIE] Error deleting cookie:", err);
  }
};

export const clearAuthCookies = () => {
  deleteCookie("token");
  deleteCookie("access_token");
  deleteCookie("refresh_token");
  localStorage.removeItem("token");
  localStorage.removeItem("auth_email");
  console.log("[🗑️ COOKIE] Cleared all auth cookies");
};

export const logout = () => {
  clearAuthCookies();
  console.log("[🚪 AUTH] Logging out...");
  window.location.href = "/";
};

// ========================
// 🎯 LOADING STATE MANAGEMENT
// ========================

let loadingCallbacks = {
  showLoader: null,
  hideLoader: null,
};

export const registerLoaderCallbacks = (showLoader, hideLoader) => {
  loadingCallbacks.showLoader = showLoader;
  loadingCallbacks.hideLoader = hideLoader;
  console.log("[🎯 LOADER] Callbacks registered");
};

export const triggerShowLoader = () => {
  if (loadingCallbacks.showLoader) {
    loadingCallbacks.showLoader();
  }
};

export const triggerHideLoader = () => {
  if (loadingCallbacks.hideLoader) {
    loadingCallbacks.hideLoader();
  }
};

// ========================
// 🔌 AXIOS INSTANCE
// ========================

const api = axios.create({
  baseURL: "http://80.225.239.163:8000",
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

// ========================
// 📤 REQUEST INTERCEPTOR - ADD TOKEN TO EVERY REQUEST
// ========================

api.interceptors.request.use(
  (config) => {
    console.log("\n[📤 REQUEST] URL:", config.url);
    console.log("[📤 REQUEST] Method:", config.method.toUpperCase());

    // Show loader on request start
    triggerShowLoader();

    // Get token from cookie (most reliable source)
    let token = getCookie("token");

    // If no token in "token" cookie, try "access_token" cookie
    if (!token) {
      token = getCookie("access_token");
    }

    // Last resort: try localStorage
    if (!token) {
      const storageToken = localStorage.getItem("token");
      if (storageToken) {
        token = storageToken;
        console.log("[📤 REQUEST] Token from localStorage");
      }
    }

    // CRITICAL: Add Authorization header if token exists
    if (token && token.length > 0) {
      config.headers.Authorization = `Bearer ${token}`;
      console.log(
        "[✅ REQUEST] Authorization header SET with token:",
        token.substring(0, 40) + "...",
      );
      console.log("[✅ REQUEST] Headers:", config.headers);
    } else {
      console.error(
        "[❌ REQUEST] NO TOKEN FOUND - Authorization header NOT SET!",
      );
      console.error(
        "[❌ REQUEST] Cookie 'token':",
        getCookie("token") ? "YES" : "NO",
      );
      console.error(
        "[❌ REQUEST] Cookie 'access_token':",
        getCookie("access_token") ? "YES" : "NO",
      );
      console.error(
        "[❌ REQUEST] localStorage 'token':",
        localStorage.getItem("token") ? "YES" : "NO",
      );
    }

    return config;
  },
  (error) => {
    console.error("[❌ REQUEST ERROR]:", error);
    triggerHideLoader();
    return Promise.reject(error);
  },
);

// ========================
// 📥 RESPONSE INTERCEPTOR
// ========================

api.interceptors.response.use(
  (response) => {
    console.log(
      "[✅ RESPONSE] Status:",
      response.status,
      "URL:",
      response.config.url,
    );
    triggerHideLoader();
    return response;
  },
  (error) => {
    console.error("[❌ RESPONSE ERROR] Status:", error.response?.status);
    console.error("[❌ RESPONSE ERROR] URL:", error.config?.url);
    console.error(
      "[❌ RESPONSE ERROR] Message:",
      error.response?.data?.message,
    );
    triggerHideLoader();
    return Promise.reject(error);
  },
);

export default api;
