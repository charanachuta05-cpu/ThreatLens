import {
  Navigate,
  Outlet,
} from "react-router-dom";

import { useAuth } from "../context/useAuth";
import type { UserRole } from "../context/AuthContextDefinition";

interface RoleRouteProps {
  allowedRoles: UserRole[];
}

function RoleRoute({
  allowedRoles,
}: RoleRouteProps) {
  const { role } = useAuth();

  if (!role) {
    return (
      <Navigate
        to="/login"
        replace
      />
    );
  }

  if (!allowedRoles.includes(role)) {
    return (
      <Navigate
        to="/dashboard"
        replace
      />
    );
  }

  return <Outlet />;
}

export default RoleRoute;