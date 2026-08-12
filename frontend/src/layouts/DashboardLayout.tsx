import { NavLink, Outlet } from "react-router-dom";
import {
  LayoutDashboard,
  ShieldAlert,
  Search,
  Bell,
  Settings,
  LogOut,
  Activity,
} from "lucide-react";
import "./DashboardLayout.css";

function DashboardLayout() {
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
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="brand-icon">
            <Activity size={22} />
          </div>

          <div>
            <h1>ThreatLens</h1>
            <span>Security Intelligence</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <p className="nav-label">MONITORING</p>

          {navigation.map((item) => {
            const Icon = item.icon;

            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `nav-item ${isActive ? "active" : ""}`
                }
              >
                <Icon size={19} />
                <span>{item.name}</span>
              </NavLink>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <NavLink to="/settings" className="nav-item">
            <Settings size={19} />
            <span>Settings</span>
          </NavLink>

          <button className="logout-button">
            <LogOut size={19} />
            <span>Logout</span>
          </button>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <span className="system-status">
              <span className="status-dot"></span>
              Threat Intelligence Engine Online
            </span>
          </div>

          <div className="topbar-user">
            <div className="user-avatar">A</div>

            <div>
              <strong>Analyst</strong>
              <span>Security Operations</span>
            </div>
          </div>
        </header>

        <section className="page-content">
          <Outlet />
        </section>
      </main>
    </div>
  );
}

export default DashboardLayout;