/**
 * useAuth — one place to read authentication + authorization state.
 *
 * Authentication is the session token cookie (set at login, survives a page
 * refresh). Authorization comes from the RBAC store (AccessContext), which
 * hydrates from localStorage synchronously and reconciles with the backend
 * shortly after mount — so on the very first render after login `user` can be
 * null for a tick while it bootstraps. Route guards account for that.
 */
import { getCookie } from "../api/api";
import { useAccess } from "../Access/AccessContext";

export default function useAuth() {
  const { currentUser, can, perms } = useAccess();

  // Any of the cookies the axios layer accepts counts as an authenticated
  // session; checking the cookie (not React state) is what makes refresh work.
  const isAuthenticated = !!(getCookie("token") || getCookie("access_token"));

  return {
    isAuthenticated,
    user: currentUser,
    role: (currentUser && currentUser.role) || null,
    can,
    perms,
  };
}
