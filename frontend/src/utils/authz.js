/**
 * Pure authorization helpers — no React, no side effects, so they can be unit
 * tested and reused by both route guards and inline UI checks.
 *
 * Roles come from the app's existing RBAC store (AccessContext):
 *   super_admin  — full access (implicitly satisfies every route)
 *   admin        — manage resources
 *   view_only    — read only
 *
 * The prompt's Admin / Manager / User map onto these as
 *   Admin -> super_admin, Manager -> admin, User -> view_only.
 *
 * This file stays free of React/context imports so it remains pure and unit
 * testable; the labels below mirror AccessContext.ROLES.
 */

// super_admin is all-access by design (see AccessContext.permsForRole).
export const SUPERUSER_ROLE = "super_admin";

const ROLE_LABELS = {
  super_admin: "Super Admin",
  admin: "Admin",
  view_only: "View Only",
};

/** Human label for a role key, e.g. "admin" -> "Admin". */
export function roleLabel(role) {
  return ROLE_LABELS[role] || role || "Unknown";
}

/** Join role keys as readable labels: ["admin","super_admin"] -> "Admin or Super Admin". */
export function roleLabels(roles) {
  const labels = (roles || []).map(roleLabel);
  if (labels.length <= 1) return labels[0] || "";
  return `${labels.slice(0, -1).join(", ")} or ${labels[labels.length - 1]}`;
}

/**
 * Does `userRole` satisfy the `roles` requirement?
 * Empty/undefined `roles` means "any authenticated user". super_admin always
 * passes.
 *
 * @param {string|null} userRole
 * @param {string[]} [roles]
 */
export function hasRequiredRole(userRole, roles) {
  if (!roles || roles.length === 0) return true;
  if (userRole === SUPERUSER_ROLE) return true;
  return roles.includes(userRole);
}

/**
 * Does the user hold the required permission action?
 * Undefined `perm` means "no permission requirement".
 *
 * @param {(action: string) => boolean} can  the AccessContext `can` predicate
 * @param {string} [perm]
 */
export function hasRequiredPerm(can, perm) {
  if (!perm) return true;
  return typeof can === "function" ? !!can(perm) : false;
}

/**
 * Combined gate used by ProtectedRoute. Both conditions must hold.
 *
 * @param {{ userRole: string|null, can: Function, roles?: string[], perm?: string }} args
 * @returns {boolean}
 */
export function isAuthorized({ userRole, can, roles, perm }) {
  return hasRequiredRole(userRole, roles) && hasRequiredPerm(can, perm);
}
