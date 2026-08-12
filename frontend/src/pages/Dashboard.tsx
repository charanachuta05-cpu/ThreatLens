import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  Activity,
  AlertTriangle,
  RefreshCw,
  ShieldAlert,
  Target,
} from "lucide-react";

import {
  getDashboardSummary,
  type DashboardSummary,
} from "../api/dashboard";

import {
  getAlerts,
  type Alert,
} from "../api/alerts";

import {
  getIndicators,
  type Indicator,
} from "../api/indicators";

import { useAlertWebSocket } from "../hooks/useAlertWebSocket";

import "./Dashboard.css";

function Dashboard() {
  const [summary, setSummary] =
    useState<DashboardSummary | null>(null);

  const [alerts, setAlerts] =
    useState<Alert[]>([]);

  const [indicators, setIndicators] =
    useState<Indicator[]>([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  /*
   * =========================================
   * LOAD DASHBOARD DATA
   * =========================================
   */

  const loadDashboard = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");

        const [
          summaryData,
          alertData,
          indicatorData,
        ] = await Promise.all([
          getDashboardSummary(),

          getAlerts({
            skip: 0,
            limit: 5,
          }),

          getIndicators({
            skip: 0,
            limit: 5,
          }),
        ]);

        setSummary(summaryData);
        setAlerts(alertData);
        setIndicators(indicatorData);
      } catch (err) {
        console.error(
          "Failed to load dashboard:",
          err,
        );

        setError(
          "Unable to load dashboard data.",
        );
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  /*
   * =========================================
   * INITIAL LOAD
   * =========================================
   *
   * setTimeout moves the state-changing
   * asynchronous operation outside the
   * synchronous effect body so that the
   * React hooks lint rule is satisfied.
   */

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadDashboard();
    }, 0);

    return () => {
      window.clearTimeout(timer);
    };
  }, [loadDashboard]);

  /*
   * =========================================
   * REAL-TIME ALERT CREATED
   * =========================================
   */

  const handleAlertCreated = useCallback(
    (newAlert: Alert) => {
      console.info(
        "[ThreatLens] Dashboard received alert.created:",
        newAlert,
      );

      setAlerts((currentAlerts) => {
        const alreadyExists =
          currentAlerts.some(
            (alert) =>
              alert.id === newAlert.id,
          );

        if (alreadyExists) {
          return currentAlerts;
        }

        return [
          newAlert,
          ...currentAlerts,
        ].slice(0, 5);
      });

      /*
       * Keep the dashboard summary's active
       * alert count synchronized when the
       * backend reports a new OPEN alert.
       */
      if (newAlert.status === "OPEN") {
        setSummary((currentSummary) => {
          if (!currentSummary) {
            return currentSummary;
          }

          return {
            ...currentSummary,
            active_alerts:
              currentSummary.active_alerts + 1,
          };
        });
      }
    },
    [],
  );

  /*
   * =========================================
   * REAL-TIME ALERT UPDATED
   * =========================================
   */

  const handleAlertUpdated = useCallback(
    (updatedAlert: Alert) => {
      console.info(
        "[ThreatLens] Dashboard received alert.updated:",
        updatedAlert,
      );

      setAlerts((currentAlerts) =>
        currentAlerts.map((alert) =>
          alert.id === updatedAlert.id
            ? {
                ...alert,
                ...updatedAlert,
              }
            : alert,
        ),
      );
    },
    [],
  );

  /*
   * =========================================
   * REAL-TIME ALERT DELETED
   * =========================================
   */

  const handleAlertDeleted = useCallback(
    (alertId: number) => {
      console.info(
        "[ThreatLens] Dashboard received alert.deleted:",
        alertId,
      );

      setAlerts((currentAlerts) =>
        currentAlerts.filter(
          (alert) =>
            alert.id !== alertId,
        ),
      );
    },
    [],
  );

  /*
   * =========================================
   * WEBSOCKET
   * =========================================
   */

  useAlertWebSocket({
    onAlertCreated:
      handleAlertCreated,

    onAlertUpdated:
      handleAlertUpdated,

    onAlertDeleted:
      handleAlertDeleted,
  });

  /*
   * =========================================
   * DERIVED METRICS
   * =========================================
   *
   * These are calculated from the actual
   * arrays returned by the API instead of
   * relying on fields that may not exist in
   * DashboardSummary.
   */

  const visibleCriticalAlerts =
    alerts.filter(
      (alert) =>
        alert.severity === "CRITICAL",
    ).length;

  const visibleOpenAlerts =
    alerts.filter(
      (alert) =>
        alert.status === "OPEN",
    ).length;

  const highRiskIndicators =
    indicators.filter(
      (indicator) =>
        indicator.severity === "HIGH" ||
        indicator.severity === "CRITICAL",
    ).length;

  const averageThreatScore =
    indicators.length > 0
      ? Math.round(
          indicators.reduce(
            (total, indicator) =>
              total +
              indicator.threat_score,
            0,
          ) / indicators.length,
        )
      : 0;

  /*
   * =========================================
   * DATE FORMATTER
   * =========================================
   */

  function formatDate(
    value: string,
  ): string {
    if (!value) {
      return "Unknown";
    }

    const date = new Date(value);

    if (
      Number.isNaN(
        date.getTime(),
      )
    ) {
      return "Unknown";
    }

    return date.toLocaleString();
  }

  /*
   * =========================================
   * LOADING STATE
   * =========================================
   */

  if (loading) {
    return (
      <div className="dashboard-page">
        <div className="dashboard-state">
          Loading dashboard...
        </div>
      </div>
    );
  }

  /*
   * =========================================
   * ERROR STATE
   * =========================================
   */

  if (error) {
    return (
      <div className="dashboard-page">
        <div className="dashboard-state error">
          <p>{error}</p>

          <button
            type="button"
            className="refresh-button"
            onClick={() =>
              void loadDashboard()
            }
          >
            <RefreshCw size={16} />

            Try Again
          </button>
        </div>
      </div>
    );
  }

  /*
   * =========================================
   * DASHBOARD
   * =========================================
   */

  return (
    <div className="dashboard-page">

      {/* =====================================
          PAGE HEADER
      ===================================== */}

      <div className="page-heading">
        <div>
          <h2>Security Dashboard</h2>

          <p>
            Monitor threat activity,
            security alerts, and
            intelligence indicators.
          </p>
        </div>

        <button
          type="button"
          className="refresh-button"
          onClick={() =>
            void loadDashboard()
          }
          disabled={loading}
        >
          <RefreshCw size={16} />

          Refresh
        </button>
      </div>

      {/* =====================================
          SUMMARY CARDS
      ===================================== */}

      <div className="dashboard-summary">

        {/* Active Alerts */}

        <div className="dashboard-summary-card">

          <div className="summary-icon">
            <ShieldAlert size={20} />
          </div>

          <div>
            <span>
              Active Alerts
            </span>

            <strong>
              {summary?.active_alerts ??
                visibleOpenAlerts}
            </strong>
          </div>

        </div>

        {/* Critical Alerts */}

        <div className="dashboard-summary-card critical">

          <div className="summary-icon">
            <AlertTriangle size={20} />
          </div>

          <div>
            <span>
              Critical Alerts
            </span>

            <strong>
              {visibleCriticalAlerts}
            </strong>
          </div>

        </div>

        {/* Indicators */}

        <div className="dashboard-summary-card">

          <div className="summary-icon">
            <Target size={20} />
          </div>

          <div>
            <span>
              Threat Indicators
            </span>

            <strong>
              {indicators.length}
            </strong>
          </div>

        </div>

        {/* High Risk */}

        <div className="dashboard-summary-card critical">

          <div className="summary-icon">
            <Activity size={20} />
          </div>

          <div>
            <span>
              High Risk Indicators
            </span>

            <strong>
              {highRiskIndicators}
            </strong>
          </div>

        </div>

      </div>

      {/* =====================================
          SECONDARY METRICS
      ===================================== */}

      <div className="dashboard-secondary">

        <div className="dashboard-metric-card">

          <span>
            Average Threat Score
          </span>

          <strong>
            {averageThreatScore}
          </strong>

        </div>

        <div className="dashboard-metric-card">

          <span>
            Visible Alerts
          </span>

          <strong>
            {alerts.length}
          </strong>

        </div>

        <div className="dashboard-metric-card">

          <span>
            Visible Indicators
          </span>

          <strong>
            {indicators.length}
          </strong>

        </div>

      </div>

      {/* =====================================
          CONTENT GRID
      ===================================== */}

      <div className="dashboard-grid">

        {/* ===================================
            RECENT ALERTS
        =================================== */}

        <div className="dashboard-card">

          <div className="dashboard-card-header">

            <div>
              <h3>
                Recent Security Alerts
              </h3>

              <span>
                Latest detected events
              </span>
            </div>

            <span className="live-status">
              Live
            </span>

          </div>

          {alerts.length === 0 ? (
            <div className="dashboard-empty">
              No recent alerts.
            </div>
          ) : (
            <div className="dashboard-alert-list">

              {alerts.map(
                (alert) => (
                  <div
                    className="dashboard-alert-item"
                    key={alert.id}
                  >

                    <div className="dashboard-alert-main">

                      <strong>
                        {alert.title}
                      </strong>

                      <span>
                        {alert.source ||
                          "Unknown source"}
                      </span>

                    </div>

                    <div className="dashboard-alert-meta">

                      <span
                        className={`severity-badge ${alert.severity.toLowerCase()}`}
                      >
                        {alert.severity}
                      </span>

                      <span className="status-badge">
                        {alert.status}
                      </span>

                      <span className="date-text">
                        {formatDate(
                          alert.created_at,
                        )}
                      </span>

                    </div>

                  </div>
                ),
              )}

            </div>
          )}

        </div>

        {/* ===================================
            RECENT INDICATORS
        =================================== */}

        <div className="dashboard-card">

          <div className="dashboard-card-header">

            <div>
              <h3>
                Threat Indicators
              </h3>

              <span>
                Latest intelligence
              </span>
            </div>

          </div>

          {indicators.length === 0 ? (
            <div className="dashboard-empty">
              No threat indicators.
            </div>
          ) : (
            <div className="dashboard-indicator-list">

              {indicators.map(
                (indicator) => (
                  <div
                    className="dashboard-indicator-item"
                    key={indicator.id}
                  >

                    <div>
                      <strong>
                        {indicator.value}
                      </strong>

                      <span>
                        {indicator.indicator_type}
                      </span>
                    </div>

                    <div className="dashboard-indicator-meta">

                      <span
                        className={`severity-badge ${indicator.severity.toLowerCase()}`}
                      >
                        {indicator.severity}
                      </span>

                      <span className="score-badge">
                        Score{" "}
                        {
                          indicator.threat_score
                        }
                      </span>

                    </div>

                  </div>
                ),
              )}

            </div>
          )}

        </div>

      </div>

    </div>
  );
}

export default Dashboard;