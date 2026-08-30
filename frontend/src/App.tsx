import {
  Navigate,
  Route,
  Routes,
} from "react-router-dom";

import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Indicators from "./pages/Indicators";
import Investigations from "./pages/Investigations";
import Settings from "./pages/Settings";

import DashboardLayout from "./layouts/DashboardLayout";
import RoleRoute from "./components/RoleRoute";

import { useAuth } from "./context/useAuth";

function App() {
  const {
    authenticated,
    loading,
  } = useAuth();

  if (loading) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#0b1120",
          color: "#f8fafc",
          fontFamily: "Arial, sans-serif",
        }}
      >
        Loading ThreatLens...
      </div>
    );
  }

  return (
    <Routes>

      {/* =========================
          Authentication
      ========================= */}

      <Route
        path="/login"
        element={
          authenticated ? (
            <Navigate
              to="/dashboard"
              replace
            />
          ) : (
            <Login />
          )
        }
      />

      <Route
        path="/register"
        element={
          authenticated ? (
            <Navigate
              to="/dashboard"
              replace
            />
          ) : (
            <Register />
          )
        }
      />

      {/* =========================
          Protected Application
      ========================= */}

      <Route
        element={
          authenticated ? (
            <DashboardLayout />
          ) : (
            <Navigate
              to="/login"
              replace
            />
          )
        }
      >

        <Route
          path="/dashboard"
          element={<Dashboard />}
        />

        <Route
          path="/indicators"
          element={<Indicators />}
        />

        {/* =========================
            Analyst/Admin Routes
        ========================= */}

        <Route
          element={
            <RoleRoute
              allowedRoles={[
                "admin",
                "analyst",
              ]}
            />
          }
        >
          <Route
            path="/investigations"
            element={<Investigations />}
          />
        </Route>

        <Route
          path="/alerts"
          element={<Alerts />}
        />

        {/* =========================
            Settings
        ========================= */}

        <Route
          path="/settings"
          element={<Settings />}
        />

      </Route>

      {/* =========================
          Unknown Routes
      ========================= */}

      <Route
        path="*"
        element={
          authenticated ? (
            <Navigate
              to="/dashboard"
              replace
            />
          ) : (
            <Navigate
              to="/login"
              replace
            />
          )
        }
      />

    </Routes>
  );
}

export default App;