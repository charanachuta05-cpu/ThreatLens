import {
  NavLink,
  Outlet,
  useNavigate,
} from "react-router-dom";

import {
  Bell,
  ClipboardList,
  GitBranch,
  LayoutDashboard,
  LogOut,
  Search,
  Settings,
  ShieldAlert,
} from "lucide-react";

import { useAuth } from "../context/useAuth";

import type {
  UserRole,
} from "../context/AuthContextDefinition";

import "./DashboardLayout.css";


interface NavigationItem {
  name: string;
  path: string;
  icon: typeof LayoutDashboard;
  allowedRoles?: UserRole[];
}


interface NavigationSection {
  label: string;
  items: NavigationItem[];
}


const navigationSections: NavigationSection[] = [
  {
    label: "MONITORING",
    items: [
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
        allowedRoles: [
          "admin",
          "analyst",
        ],
      },
      {
        name: "Alerts",
        path: "/alerts",
        icon: Bell,
      },
    ],
  },

  {
    label: "ANALYSIS",
    items: [
      {
        name: "Correlation",
        path: "/correlation",
        icon: GitBranch,
        allowedRoles: [
          "admin",
          "analyst",
        ],
      },
      {
        name: "Incidents",
        path: "/incidents",
        icon: ClipboardList,
        allowedRoles: [
          "admin",
          "analyst",
        ],
      },
    ],
  },

  {
    label: "SYSTEM",
    items: [
      {
        name: "Settings",
        path: "/settings",
        icon: Settings,
      },
    ],
  },
];


function formatRole(
  role: UserRole | null,
): string {
  if (!role) {
    return "User";
  }

  return (
    role.charAt(0).toUpperCase()
    + role.slice(1)
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
  const navigate = useNavigate();

  const {
    logout,
    role,
  } = useAuth();


  const formattedRole =
    formatRole(role);

  const roleDescription =
    getRoleDescription(role);


  const visibleSections =
    navigationSections
      .map((section) => ({
        ...section,

        items: section.items.filter(
          (item) =>
            !item.allowedRoles
            || (
              role
              && item.allowedRoles.includes(
                role,
              )
            ),
        ),
      }))
      .filter(
        (section) =>
          section.items.length > 0,
      );


  function handleLogout() {
    logout();

    navigate(
      "/login",
      {
        replace: true,
      },
    );
  }


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
          {visibleSections.map(
            (section) => (
              <div
                key={section.label}
                className="nav-group"
              >
                <p className="nav-label">
                  {section.label}
                </p>

                <div className="nav-group-items">
                  {section.items.map(
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
                </div>
              </div>
            ),
          )}
        </nav>


        {/* Bottom Controls */}

        <div className="sidebar-bottom">
          <button
            type="button"
            className="logout-button"
            onClick={handleLogout}
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