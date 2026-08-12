import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  AlertTriangle,
  Clock,
  Filter,
  RefreshCw,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";

import {
  getAlerts,
  type Alert,
  type AlertQuery,
} from "../api/alerts";

import { useAlertWebSocket } from "../hooks/useAlertWebSocket";

import "./Alerts.css";

function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const [search, setSearch] =
    useState("");

  const [severity, setSeverity] =
    useState("");

  const [status, setStatus] =
    useState("");

  const [source, setSource] =
    useState("");

  const loadAlerts = useCallback(
    async (query: AlertQuery = {}) => {
      try {
        setLoading(true);
        setError("");

        const data = await getAlerts({
          skip: 0,
          limit: 50,
          ...query,
        });

        setAlerts((currentAlerts) => {
          const apiIds = new Set(
            data.map(
              (alert) => alert.id,
            ),
          );

          const liveAlerts =
            currentAlerts.filter(
              (alert) =>
                !apiIds.has(alert.id),
            );

          return [
            ...liveAlerts,
            ...data,
          ].slice(0, 50);
        });
      } catch (err) {
        console.error(
          "Failed to load alerts:",
          err,
        );

        setError(
          "Unable to load alerts.",
        );
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadAlerts({
        search:
          search.trim() || undefined,
        severity:
          severity || undefined,
        status:
          status || undefined,
        source:
          source.trim() || undefined,
      });
    }, 0);

    return () => {
      window.clearTimeout(timer);
    };
  }, [
    search,
    severity,
    status,
    source,
    loadAlerts,
  ]);

  /*
   * =========================================
   * REAL-TIME ALERT HANDLERS
   * =========================================
   */

  const handleAlertCreated =
    useCallback(
      (newAlert: Alert) => {
        console.info(
          "[ThreatLens] React received alert.created:",
          newAlert,
        );

        setAlerts(
          (currentAlerts) => {
            const alreadyExists =
              currentAlerts.some(
                (alert) =>
                  alert.id ===
                  newAlert.id,
              );

            if (alreadyExists) {
              return currentAlerts;
            }

            return [
              newAlert,
              ...currentAlerts,
            ].slice(0, 50);
          },
        );
      },
      [],
    );

  const handleAlertUpdated =
    useCallback(
      (updatedAlert: Alert) => {
        console.info(
          "[ThreatLens] React received alert.updated:",
          updatedAlert,
        );

        setAlerts(
          (currentAlerts) =>
            currentAlerts.map(
              (alert) =>
                alert.id ===
                updatedAlert.id
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

  const handleAlertDeleted =
    useCallback(
      (alertId: number) => {
        console.info(
          "[ThreatLens] React received alert.deleted:",
          alertId,
        );

        setAlerts(
          (currentAlerts) =>
            currentAlerts.filter(
              (alert) =>
                alert.id !== alertId,
            ),
        );
      },
      [],
    );

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
   * HELPERS
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

  function severityClass(
    value: string,
  ): string {
    return `severity-badge ${value.toLowerCase()}`;
  }

  function clearFilters(): void {
    setSearch("");
    setSeverity("");
    setStatus("");
    setSource("");
  }

  const hasFilters =
    Boolean(
      search ||
        severity ||
        status ||
        source,
    );

  const criticalCount =
    alerts.filter(
      (alert) =>
        alert.severity ===
        "CRITICAL",
    ).length;

  const openCount =
    alerts.filter(
      (alert) =>
        alert.status === "OPEN",
    ).length;

  return (
    <div className="alerts-page">

      {/* =================================
          PAGE HEADER
      ================================= */}

      <div className="page-heading">
        <div>
          <h2>Security Alerts</h2>

          <p>
            Monitor, review, and investigate
            detected security events.
          </p>
        </div>

        <button
          type="button"
          className="refresh-button"
          onClick={() =>
            void loadAlerts({
              search:
                search.trim() ||
                undefined,
              severity:
                severity ||
                undefined,
              status:
                status ||
                undefined,
              source:
                source.trim() ||
                undefined,
            })
          }
          disabled={loading}
        >
          <RefreshCw
            size={16}
            className={
              loading
                ? "refresh-spinning"
                : ""
            }
          />

          Refresh
        </button>
      </div>

      {/* =================================
          ALERT SUMMARY
      ================================= */}

      <div className="alerts-summary">

        <div className="alert-summary-card">
          <ShieldAlert size={20} />

          <div>
            <span>Total Alerts</span>

            <strong>
              {alerts.length}
            </strong>
          </div>
        </div>

        <div className="alert-summary-card critical">
          <AlertTriangle size={20} />

          <div>
            <span>Critical</span>

            <strong>
              {criticalCount}
            </strong>
          </div>
        </div>

        <div className="alert-summary-card">
          <Clock size={20} />

          <div>
            <span>Open</span>

            <strong>
              {openCount}
            </strong>
          </div>
        </div>

      </div>

      {/* =================================
          FILTERS
      ================================= */}

      <div className="alerts-filters">

        <div className="filter-heading">
          <Filter size={15} />

          <span>
            Alert Filters
          </span>
        </div>

        <div className="filter-grid">

          <div className="filter-input">
            <Search size={15} />

            <input
              type="text"
              value={search}
              onChange={(event) =>
                setSearch(
                  event.target.value,
                )
              }
              placeholder="Search alerts..."
            />
          </div>

          <select
            value={severity}
            onChange={(event) =>
              setSeverity(
                event.target.value,
              )
            }
            aria-label="Filter by severity"
          >
            <option value="">
              All Severities
            </option>

            <option value="CRITICAL">
              Critical
            </option>

            <option value="HIGH">
              High
            </option>

            <option value="MEDIUM">
              Medium
            </option>

            <option value="LOW">
              Low
            </option>
          </select>

          <select
            value={status}
            onChange={(event) =>
              setStatus(
                event.target.value,
              )
            }
            aria-label="Filter by status"
          >
            <option value="">
              All Statuses
            </option>

            <option value="OPEN">
              Open
            </option>

            <option value="IN_PROGRESS">
              In Progress
            </option>

            <option value="RESOLVED">
              Resolved
            </option>

            <option value="CLOSED">
              Closed
            </option>
          </select>

          <div className="filter-input">
            <input
              type="text"
              value={source}
              onChange={(event) =>
                setSource(
                  event.target.value,
                )
              }
              placeholder="Source..."
            />
          </div>

          {hasFilters && (
            <button
              type="button"
              className="clear-filters-button"
              onClick={clearFilters}
            >
              <X size={14} />

              Clear
            </button>
          )}

        </div>
      </div>

      {/* =================================
          ALERT QUEUE
      ================================= */}

      <div className="alerts-card">

        <div className="alerts-card-header">
          <div>
            <h3>Alert Queue</h3>

            <span>
              Latest security events
            </span>
          </div>

          <div className="live-indicator">
            <span className="live-dot" />
            Live
          </div>
        </div>

        {loading && (
          <div className="alerts-state">
            Loading alerts...
          </div>
        )}

        {!loading && error && (
          <div className="alerts-state error">
            <span>{error}</span>

            <button
              type="button"
              onClick={() =>
                void loadAlerts({
                  search:
                    search.trim() ||
                    undefined,
                  severity:
                    severity ||
                    undefined,
                  status:
                    status ||
                    undefined,
                  source:
                    source.trim() ||
                    undefined,
                })
              }
              className="retry-button"
            >
              Try Again
            </button>
          </div>
        )}

        {!loading &&
          !error &&
          alerts.length === 0 && (
            <div className="alerts-state">
              {hasFilters
                ? "No alerts match the selected filters."
                : "No alerts available."}
            </div>
          )}

        {!loading &&
          !error &&
          alerts.length > 0 && (
            <div className="alert-table-wrapper">

              <table className="alert-table">

                <thead>
                  <tr>
                    <th>Alert</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Source</th>
                    <th>Created</th>
                  </tr>
                </thead>

                <tbody>
                  {alerts.map(
                    (alert) => (
                      <tr
                        key={alert.id}
                      >
                        <td>
                          <div className="alert-title">

                            <strong>
                              {alert.title}
                            </strong>

                            {alert.description && (
                              <span>
                                {
                                  alert.description
                                }
                              </span>
                            )}

                          </div>
                        </td>

                        <td>
                          <span
                            className={severityClass(
                              alert.severity,
                            )}
                          >
                            {alert.severity}
                          </span>
                        </td>

                        <td>
                          <span
                            className={`status-badge status-${alert.status.toLowerCase()}`}
                          >
                            {alert.status.replace(
                              "_",
                              " ",
                            )}
                          </span>
                        </td>

                        <td>
                          <span className="source-text">
                            {alert.source ||
                              "Unknown"}
                          </span>
                        </td>

                        <td>
                          <span className="date-text">
                            {formatDate(
                              alert.created_at,
                            )}
                          </span>
                        </td>
                      </tr>
                    ),
                  )}
                </tbody>

              </table>

            </div>
          )}

      </div>
    </div>
  );
}

export default Alerts;