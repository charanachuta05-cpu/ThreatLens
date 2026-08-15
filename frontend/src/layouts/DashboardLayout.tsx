import {
  NavLink,
  Outlet,
} from "react-router-dom";

import {
  LayoutDashboard,
  ShieldAlert,
  Search,
  Bell,
  Settings,
  LogOut,
} from "lucide-react";

import { useAuth } from "../context/useAuth";
import type { UserRole } from "../context/AuthContextDefinition";

import "./DashboardLayout.css";

interface NavigationItem {
  name: string;
  path: string;
  icon: typeof LayoutDashboard;
  allowedRoles?: UserRole[];
}

const navigation: NavigationItem[] = [
  {
    name: "Dashboard",
    path: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    name: "Indicators",
    path: "/indicators",
    icon: Search,
  },
  {
    name: "Investigations",
    path: "/investigations",
    icon: ShieldAlert,
    allowedRoles: ["admin", "analyst"],
  },
  {
    name: "Alerts",
    path: "/alerts",
    icon: Bell,
  },
];

function formatRole(
  role: UserRole | null,
): string {
  if (!role) {
    return "User";
  }

  return (
    role.charAt(0).toUpperCase() +
    role.slice(1)
  );
}

function getRoleDescription(
  role: UserRole | null,
): string {
  switch (role) {
    case "admin":
      return "Security Administrator";

    case "analyst":
      return "Security Operations";

    case "viewer":
      return "Read-only Access";

    default:
      return "Security Operations";
  }
}

function DashboardLayout() {
  const {
    logout,
    role,
  } = useAuth();

  const formattedRole =
    formatRole(role);

  const roleDescription =
    getRoleDescription(role);

  return (
    <div className="dashboard-layout">

      {/* ==========================================
          Sidebar
      ========================================== */}

      <aside className="sidebar">

        {/* Brand */}

        <div className="sidebar-brand">

          <div>
            <h1>
              ThreatLens
            </h1>

            <span>
              Security Intelligence
            </span>
          </div>

        </div>

        {/* Navigation */}

        <nav
          className="sidebar-nav"
          aria-label="Primary navigation"
        >

          <p className="nav-label">
            MONITORING
          </p>

          {navigation.map(
            (item) => {
              const Icon =
                item.icon;

              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({
                    isActive,
                  }) =>
                    `nav-item ${
                      isActive
                        ? "active"
                        : ""
                    }`
                  }
                >
                  <Icon
                    size={19}
                    aria-hidden="true"
                  />

                  <span>
                    {item.name}
                  </span>
                </NavLink>
              );
            },
          )}

        </nav>

        {/* Bottom Controls */}

        <div className="sidebar-bottom">

          <NavLink
            to="/settings"
            className={({ isActive }) =>
              `nav-item ${
                isActive
                  ? "active"
                  : ""
              }`
            }
          >
            <Settings
              size={19}
              aria-hidden="true"
            />

            <span>
              Settings
            </span>
          </NavLink>

          <button
            type="button"
            className="logout-button"
            onClick={logout}
          >
            <LogOut
              size={19}
              aria-hidden="true"
            />

            <span>
              Logout
            </span>
          </button>

        </div>

      </aside>

      {/* ==========================================
          Main Content
      ========================================== */}

      <main className="main-content">

        {/* Top Bar */}

        <header className="topbar">

          <div>
            <span className="system-status">

              <span
                className="status-dot"
                aria-hidden="true"
              />

              Threat Intelligence
              Engine Online

            </span>
          </div>

          {/* Authenticated User */}

          <div className="topbar-user">

            <div
              className="user-avatar"
              aria-hidden="true"
            >
              {formattedRole
                .charAt(0)
                .toUpperCase()}
            </div>

            <div className="topbar-user-info">

              <strong>
                {formattedRole}
              </strong>

              <span>
                {roleDescription}
              </span>

            </div>

          </div>

        </header>

        {/* Page Content */}

        <div className="page-content">
          <Outlet />
        </div>

      </main>

    </div>
  );
}

export default DashboardLayout;