import {
  Activity,
  CheckCircle2,
  Database,
  KeyRound,
  LogOut,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  User,
  Users,
} from "lucide-react";

import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  getAdminDashboard,
  getCurrentUser,
  getHealthStatus,
  type CurrentUser,
  type HealthStatus,
} from "../api/users";

import { useAuth } from "../context/useAuth";

import "./Settings.css";

function getRoleDescription(
  role: string | null,
): string {
  switch (role) {
    case "admin":
      return "Security Administrator";

    case "analyst":
      return "Security Operations";

    case "viewer":
      return "Read-only Access";

    default:
      return "Authenticated User";
  }
}

function Settings() {
  const {
    role,
    logout,
  } = useAuth();

  const [user, setUser] =
    useState<CurrentUser | null>(null);

  const [health, setHealth] =
    useState<HealthStatus | null>(null);

  const [
    adminVerified,
    setAdminVerified,
  ] = useState(false);

  const [loading, setLoading] =
    useState(true);

  const [
    refreshing,
    setRefreshing,
  ] = useState(false);

  const [error, setError] =
    useState<string | null>(null);

  const loadSettings = useCallback(
    async () => {
      setRefreshing(true);
      setError(null);

      try {
        const [
          currentUser,
          systemHealth,
        ] = await Promise.all([
          getCurrentUser(),
          getHealthStatus(),
        ]);

        setUser(currentUser);
        setHealth(systemHealth);

        if (
          currentUser.role ===
          "admin"
        ) {
          try {
            await getAdminDashboard();

            setAdminVerified(true);
          } catch {
            setAdminVerified(false);
          }
        } else {
          setAdminVerified(false);
        }
      } catch {
        setError(
          "Unable to refresh ThreatLens settings. Please verify the API connection and try again.",
        );
      } finally {
        setRefreshing(false);
      }
    },
    [],
  );

  useEffect(() => {
    let cancelled = false;

    async function initializeSettings() {
      try {
        const [
          currentUser,
          systemHealth,
        ] = await Promise.all([
          getCurrentUser(),
          getHealthStatus(),
        ]);

        if (cancelled) {
          return;
        }

        setUser(currentUser);
        setHealth(systemHealth);

        if (
          currentUser.role ===
          "admin"
        ) {
          try {
            await getAdminDashboard();

            if (!cancelled) {
              setAdminVerified(true);
            }
          } catch {
            if (!cancelled) {
              setAdminVerified(false);
            }
          }
        } else if (!cancelled) {
          setAdminVerified(false);
        }
      } catch {
        if (!cancelled) {
          setError(
            "Unable to load ThreatLens settings. Please verify the API connection and try again.",
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void initializeSettings();

    return () => {
      cancelled = true;
    };
  }, []);

  const roleDescription =
    getRoleDescription(role);

  const apiHealthy =
    health?.status?.toLowerCase() ===
    "healthy";

  const databaseHealthy =
    health?.database?.toLowerCase() ===
    "connected";

  if (loading) {
    return (
      <div className="settings-loading">
        <RefreshCw
          size={22}
          className="settings-spin"
          aria-hidden="true"
        />

        <span>
          Loading security settings...
        </span>
      </div>
    );
  }

  return (
    <div className="settings-page">

      {/* Header */}

      <header className="settings-header">
        <div>
          <p className="settings-eyebrow">
            SYSTEM
          </p>

          <h1>
            Settings
          </h1>

          <p className="settings-subtitle">
            Review your ThreatLens account,
            security access, intelligence
            capabilities and live platform
            status.
          </p>
        </div>

        <button
          type="button"
          className="settings-refresh-button"
          onClick={() =>
            void loadSettings()
          }
          disabled={refreshing}
        >
          <RefreshCw
            size={16}
            aria-hidden="true"
            className={
              refreshing
                ? "settings-spin"
                : ""
            }
          />

          {refreshing
            ? "Refreshing..."
            : "Refresh Status"}
        </button>
      </header>

      {/* Error */}

      {error && (
        <div
          className="settings-error"
          role="alert"
        >
          <Shield
            size={17}
            aria-hidden="true"
          />

          <span>
            {error}
          </span>
        </div>
      )}

      {/* Settings Cards */}

      <section
        className="settings-grid"
        aria-label="ThreatLens settings"
      >

        {/* My Account */}

        <article className="settings-card">
          <div className="settings-card-heading">
            <div className="settings-icon">
              <User
                size={20}
                aria-hidden="true"
              />
            </div>

            <div>
              <h2>
                My Account
              </h2>

              <p>
                Authenticated ThreatLens
                identity
              </p>
            </div>
          </div>

          <div className="settings-details">
            <div className="settings-detail">
              <span>
                Username
              </span>

              <strong>
                {user?.username ?? "—"}
              </strong>
            </div>

            <div className="settings-detail">
              <span>
                Email
              </span>

              <strong>
                {user?.email ?? "—"}
              </strong>
            </div>

            <div className="settings-detail">
              <span>
                User ID
              </span>

              <strong>
                {user?.id ?? "—"}
              </strong>
            </div>

            <div className="settings-detail">
              <span>
                Role
              </span>

              <strong className="settings-role">
                {user?.role
                  ? user.role.toUpperCase()
                  : "—"}
              </strong>
            </div>
          </div>
        </article>

        {/* Access & Security */}

        <article className="settings-card">
          <div className="settings-card-heading">
            <div className="settings-icon">
              <ShieldCheck
                size={20}
                aria-hidden="true"
              />
            </div>

            <div>
              <h2>
                Access & Security
              </h2>

              <p>
                Authentication and
                authorization state
              </p>
            </div>
          </div>

          <div className="settings-status-list">
            <div>
              <CheckCircle2
                size={17}
                aria-hidden="true"
              />

              <span>
                JWT authentication active
              </span>
            </div>

            <div>
              <Shield
                size={17}
                aria-hidden="true"
              />

              <span>
                Role-based access control
                enabled
              </span>
            </div>

            <div>
              <KeyRound
                size={17}
                aria-hidden="true"
              />

              <span>
                Access level:
                {" "}
                <strong>
                  {roleDescription}
                </strong>
              </span>
            </div>

            <div>
              <CheckCircle2
                size={17}
                aria-hidden="true"
              />

              <span>
                Authenticated API requests
                protected with bearer
                authorization
              </span>
            </div>
          </div>
        </article>

        {/* Threat Intelligence */}

        <article className="settings-card">
          <div className="settings-card-heading">
            <div className="settings-icon">
              <Activity
                size={20}
                aria-hidden="true"
              />
            </div>

            <div>
              <h2>
                Threat Intelligence
              </h2>

              <p>
                Intelligence engine
                capabilities
              </p>
            </div>
          </div>

          <div className="settings-status-list">
            <div>
              <CheckCircle2
                size={17}
                aria-hidden="true"
              />

              <span>
                IOC enrichment pipeline
                available
              </span>
            </div>

            <div>
              <CheckCircle2
                size={17}
                aria-hidden="true"
              />

              <span>
                Threat, reputation and
                confidence scoring
              </span>
            </div>

            <div>
              <CheckCircle2
                size={17}
                aria-hidden="true"
              />

              <span>
                Automatic high-risk alert
                generation
              </span>
            </div>

            <div>
              <CheckCircle2
                size={17}
                aria-hidden="true"
              />

              <span>
                Investigation and indicator
                correlation workflow
              </span>
            </div>

            <div>
              <CheckCircle2
                size={17}
                aria-hidden="true"
              />

              <span>
                Supported IOC types:
                IP, Domain, URL and Hash
              </span>
            </div>
          </div>
        </article>

        {/* Platform Status */}

        <article className="settings-card">
          <div className="settings-card-heading">
            <div className="settings-icon">
              <Server
                size={20}
                aria-hidden="true"
              />
            </div>

            <div>
              <h2>
                Platform Status
              </h2>

              <p>
                Live application health
              </p>
            </div>
          </div>

          <div className="settings-health">
            <div>
              <Activity
                size={18}
                aria-hidden="true"
              />

              <span>
                ThreatLens API
              </span>

              <strong
                className={
                  apiHealthy
                    ? "status-healthy"
                    : "status-warning"
                }
              >
                {health?.status ??
                  "Unknown"}
              </strong>
            </div>

            <div>
              <Database
                size={18}
                aria-hidden="true"
              />

              <span>
                PostgreSQL Database
              </span>

              <strong
                className={
                  databaseHealthy
                    ? "status-healthy"
                    : "status-warning"
                }
              >
                {health?.database ??
                  "Unknown"}
              </strong>
            </div>

            <div>
              <ShieldCheck
                size={18}
                aria-hidden="true"
              />

              <span>
                Authentication
              </span>

              <strong className="status-healthy">
                Protected
              </strong>
            </div>

            <div>
              <Activity
                size={18}
                aria-hidden="true"
              />

              <span>
                Intelligence Engine
              </span>

              <strong
                className={
                  apiHealthy
                    ? "status-healthy"
                    : "status-warning"
                }
              >
                {apiHealthy
                  ? "Online"
                  : "Unknown"}
              </strong>
            </div>
          </div>
        </article>

        {/* Admin Only */}

        {role === "admin" && (
          <article className="settings-card settings-admin-card">
            <div className="settings-card-heading">
              <div className="settings-icon settings-admin-icon">
                <Users
                  size={20}
                  aria-hidden="true"
                />
              </div>

              <div>
                <h2>
                  Administrator Access
                </h2>

                <p>
                  Restricted ThreatLens
                  system privileges
                </p>
              </div>
            </div>

            <div className="settings-status-list">
              <div>
                {adminVerified ? (
                  <CheckCircle2
                    size={17}
                    aria-hidden="true"
                  />
                ) : (
                  <Shield
                    size={17}
                    aria-hidden="true"
                  />
                )}

                <span>
                  Administrator API:
                  {" "}
                  <strong>
                    {adminVerified
                      ? "Verified"
                      : "Unavailable"}
                  </strong>
                </span>
              </div>

              <div>
                <ShieldCheck
                  size={17}
                  aria-hidden="true"
                />

                <span>
                  Persistent security audit
                  events available to
                  administrators
                </span>
              </div>

              <div>
                <KeyRound
                  size={17}
                  aria-hidden="true"
                />

                <span>
                  Elevated operations
                  protected by backend
                  role-based authorization
                </span>
              </div>
            </div>

            <div className="settings-admin-note">
              Administrative functionality
              remains protected by backend
              authorization even if a client
              attempts to bypass the user
              interface.
            </div>
          </article>
        )}

        {/* Session */}

        <article className="settings-card">
          <div className="settings-card-heading">
            <div className="settings-icon">
              <LogOut
                size={20}
                aria-hidden="true"
              />
            </div>

            <div>
              <h2>
                Session
              </h2>

              <p>
                Current authenticated
                browser session
              </p>
            </div>
          </div>

          <p className="settings-session-text">
            You are currently authenticated
            as
            {" "}
            <strong>
              {user?.username ??
                "ThreatLens user"}
            </strong>
            .
            Signing out removes the local
            authentication session from
            this browser.
          </p>

          <button
            type="button"
            className="settings-logout-button"
            onClick={logout}
          >
            <LogOut
              size={17}
              aria-hidden="true"
            />

            Sign Out
          </button>
        </article>
      </section>

      {/* Security Notice */}

      <div className="settings-notice">
        <ShieldCheck
          size={16}
          aria-hidden="true"
        />

        <span>
          Security-sensitive configuration
          such as password management and
          account preferences is not exposed
          until dedicated protected backend
          endpoints are implemented.
        </span>
      </div>
    </div>
  );
}

export default Settings;