import React from "react";
import { ROLES } from "../AccessContext";

const CLASS = {
  super_admin: "rbac-role-super",
  admin: "rbac-role-admin",
  view_only: "rbac-role-view",
};

export default function RoleBadge({ role }) {
  return (
    <span className={`rbac-role-badge ${CLASS[role] || ""}`}>
      {ROLES[role]?.label || role}
    </span>
  );
}
