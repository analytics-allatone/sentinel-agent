import React from "react";
import RoleBadge from "./RoleBadge";
import { effectivePerms } from "../AccessContext";

function initials(user) {
  const base = user.name || user.email;
  return base.slice(0, 2).toUpperCase();
}

function permSummary(user) {
  const p = effectivePerms(user);
  if (user.status !== "active") return "—";
  if (p.manageUsers) return "Full access";
  const parts = [];
  if (p.view && p.create && p.edit && p.delete)  return "Admin access";
  
  else if (p.view) return "View only";
  else return   "None";
}

function fmt(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  } catch {
    return "—";
  }
}

/**
 * props:
 *  - users, currentUserId
 *  - canManage (bool) — show/hide the action controls
 *  - onEdit, onToggleStatus, onRemove
 */
export default function UsersTable({
  users,
  currentUserId,
  canManage,
  onEdit,
  onToggleStatus,
  onRemove,
}) {
  if (users.length === 0) {
    return <div className="rbac-empty">No users match your search.</div>;
  }

  return (
    <div className="rbac-table-wrap">
      <table className="rbac-table">
        <thead>
          <tr>
            <th>User</th>
            <th>Role</th>
            <th>Permissions</th>
            <th>Status</th>
            <th>Invited</th>
            {canManage && <th className="rbac-th-actions">Actions</th>}
          </tr>
        </thead>
        <tbody>
          {users.map((u) => {
            const isSuper = u.role === "super_admin";
            const isSelf = u.id === currentUserId;
            return (
              <tr key={u.id} className={u.status !== "active" ? "rbac-row-disabled" : ""}>
                <td>
                  <div className="rbac-user-cell">
                    <span className={`rbac-avatar rbac-avatar-${u.role}`}>{initials(u)}</span>
                    <div className="rbac-user-meta">
                      <span className="rbac-user-name">
                        {u.name} {isSelf && <span className="rbac-you">you</span>}
                      </span>
                      <span className="rbac-user-email">{u.email}</span>
                    </div>
                  </div>
                </td>
                <td>
                  <RoleBadge role={u.role} />
                </td>
                <td className="rbac-perm-cell">{permSummary(u)}</td>
                <td>
                  <span className={`rbac-status rbac-status-${u.status}`}>
                    <span className="rbac-status-dot" />
                    {u.status === "active" ? "Active" : "Disabled"}
                  </span>
                </td>
                <td className="rbac-date-cell">{fmt(u.invitedAt)}</td>
                {canManage && (
                  <td>
                    <div className="rbac-actions">
                      <button
                        className="rbac-action"
                        onClick={() => onEdit(u)}
                        disabled={isSuper}
                        title={isSuper ? "Super Admin is not editable" : "Edit access"}
                      >
                        Edit
                      </button>
                      <button
                        className="rbac-action"
                        onClick={() => onToggleStatus(u)}
                        disabled={isSuper}
                        title={isSuper ? "Cannot disable Super Admin" : "Enable / disable"}
                      >
                        {u.status === "active" ? "Disable" : "Enable"}
                      </button>
                      <button
                        className="rbac-action rbac-action-danger"
                        onClick={() => onRemove(u)}
                        disabled={isSuper}
                        title={isSuper ? "Cannot remove Super Admin" : "Remove access"}
                      >
                        Remove
                      </button>
                    </div>
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
