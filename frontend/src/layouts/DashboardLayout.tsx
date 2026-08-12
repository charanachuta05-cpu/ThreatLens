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

import "./DashboardLayout.css";

function DashboardLayout() {
  const { logout } = useAuth();

  const navigation = [
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
    },
    {
      name: "Alerts",
      path: "/alerts",
      icon: Bell,
    },
  ];

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

        <nav className="sidebar-nav">

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
                  <Icon size={19} />

                  <span>
                    {item.name}
                  </span>
                </NavLink>
              );
            }
          )}

        </nav>

        {/* Bottom Controls */}

        <div className="sidebar-bottom">

          <NavLink
            to="/settings"
            className="nav-item"
          >
            <Settings size={19} />

            <span>
              Settings
            </span>
          </NavLink>

          <button
            type="button"
            className="logout-button"
            onClick={logout}
          >
            <LogOut size={19} />

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

              <span className="status-dot" />

              Threat Intelligence Engine Online

            </span>
          </div>

          <div className="topbar-user">

            <div className="user-avatar">
              A
            </div>

            <div>
              <strong>
                Analyst
              </strong>

              <span>
                Security Operations
              </span>
            </div>

          </div>

        </header>

        {/* Page */}

        <section className="page-content">
          <Outlet />
        </section>

      </main>

    </div>
  );
}

export default DashboardLayout;