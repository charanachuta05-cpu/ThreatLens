import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  ChevronRight,
  Clock,
  ExternalLink,
  Filter,
  RefreshCw,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

import {
  getAlerts,
  type Alert,
} from "../api/alerts";

import "./Alerts.css";

interface AlertFilters {
  search?: string;
  severity?: string;
  status?: string;
  source?: string;
}

function formatDate(
  value: string | null | undefined,
): string {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return date.toLocaleString();
}

function severityClass(
  severity: string | null | undefined,
): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return "severity-critical";

    case "HIGH":
      return "severity-high";

    case "MEDIUM":
      return "severity-medium";

    case "LOW":
      return "severity-low";

    default:
      return "severity-unknown";
  }
}

function statusClass(
  status: string | null | undefined,
): string {
  switch (status?.toUpperCase()) {
    case "OPEN":
      return "status-open";

    case "IN_PROGRESS":
      return "status-in_progress";

    case "RESOLVED":
      return "status-resolved";

    default:
      return "status-unknown";
  }
}

function formatStatus(
  status: string | null | undefined,
): string {
  if (!status) {
    return "Unknown";
  }

  return status
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}

function getApiErrorMessage(
  error: unknown,
): string {
  if (!axios.isAxiosError(error)) {
    return "Unable to load alerts.";
  }

  switch (error.response?.status) {
    case 401:
      return "Your session has expired. Please log in again.";

    case 403:
      return "You do not have permission to view alerts.";

    case 404:
      return "Alert endpoint was not found.";

    case 422:
      return "Invalid alert filter parameters.";

    default:
      return "Unable to load alerts.";
  }
}

function Alerts() {
  const navigate = useNavigate();

  const [alerts, setAlerts] =
    useState<Alert[]>([]);

  const [search, setSearch] =
    useState("");

  const [severity, setSeverity] =
    useState("");

  const [status, setStatus] =
    useState("");

  const [source, setSource] =
    useState("");

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState("");

  const [
    selectedAlertId,
    setSelectedAlertId,
  ] = useState<number | null>(null);

  /*
   * =========================================
   * FILTER STATE
   * =========================================
   */

  const hasFilters =
    Boolean(
      search.trim() ||
        severity ||
        status ||
        source.trim(),
    );

  /*
   * =========================================
   * LOAD ALERTS
   * =========================================
   */

  const loadAlerts = useCallback(
    async (
      filters: AlertFilters = {},
      options?: {
        silent?: boolean;
      },
    ) => {
      const silent =
        options?.silent ?? false;

      try {
        if (silent) {
          setRefreshing(true);
        } else {
          setLoading(true);
        }

        setError("");

        const data =
          await getAlerts({
            skip: 0,
            limit: 100,

            search:
              filters.search ||
              undefined,

            severity:
              filters.severity ||
              undefined,

            status:
              filters.status ||
              undefined,

            source:
              filters.source ||
              undefined,
          });

        setAlerts(data);
      } catch (err) {
        console.error(
          "Failed to load alerts:",
          err,
        );

        setError(
          getApiErrorMessage(err),
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [],
  );

  /*
   * =========================================
   * INITIAL LOAD + FILTER APPLICATION
   *
   * A single effect handles both operations.
   *
   * The timeout prevents the React
   * set-state-in-effect lint violation and
   * debounces filter changes.
   * =========================================
   */

  useEffect(() => {
    const timer =
      window.setTimeout(() => {
        const hasActiveFilters =
          Boolean(
            search.trim() ||
              severity ||
              status ||
              source.trim(),
          );

        void loadAlerts(
          {
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
          },
          {
            silent: hasActiveFilters,
          },
        );
      }, 350);

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
   * VISIBLE ALERTS
   *
   * Backend filtering is authoritative.
   * This local filtering provides an additional
   * safety layer if the backend returns broader
   * results.
   * =========================================
   */

  const visibleAlerts =
    useMemo(() => {
      const normalizedSearch =
        search
          .trim()
          .toLowerCase();

      const normalizedSource =
        source
          .trim()
          .toLowerCase();

      return alerts.filter(
        (alert) => {
          const title =
            alert.title
              ?.toLowerCase() ??
            "";

          const description =
            alert.description
              ?.toLowerCase() ??
            "";

          const alertSource =
            alert.source
              ?.toLowerCase() ??
            "";

          const matchesSearch =
            !normalizedSearch ||
            title.includes(
              normalizedSearch,
            ) ||
            description.includes(
              normalizedSearch,
            );

          const matchesSeverity =
            !severity ||
            alert.severity ===
              severity;

          const matchesStatus =
            !status ||
            alert.status ===
              status;

          const matchesSource =
            !normalizedSource ||
            alertSource.includes(
              normalizedSource,
            );

          return (
            matchesSearch &&
            matchesSeverity &&
            matchesStatus &&
            matchesSource
          );
        },
      );
    }, [
      alerts,
      search,
      severity,
      status,
      source,
    ]);

  /*
   * =========================================
   * SUMMARY STATISTICS
   * =========================================
   */

  const totalCount =
    visibleAlerts.length;

  const criticalCount =
    visibleAlerts.filter(
      (alert) =>
        alert.severity ===
        "CRITICAL",
    ).length;

  const highCount =
    visibleAlerts.filter(
      (alert) =>
        alert.severity ===
        "HIGH",
    ).length;

  const openCount =
    visibleAlerts.filter(
      (alert) =>
        alert.status ===
          "OPEN" ||
        alert.status ===
          "IN_PROGRESS",
    ).length;

  const resolvedCount =
    visibleAlerts.filter(
      (alert) =>
        alert.status ===
        "RESOLVED",
    ).length;

  /*
   * =========================================
   * FILTER ACTIONS
   * =========================================
   */

  function clearFilters() {
    setSearch("");
    setSeverity("");
    setStatus("");
    setSource("");
    setSelectedAlertId(null);
  }

  function refreshAlerts() {
    void loadAlerts(
      {
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
      },
      {
        silent: true,
      },
    );
  }

  /*
   * =========================================
   * INVESTIGATION NAVIGATION
   *
   * Investigations currently supports:
   *
   * /investigations?indicator=42
   * =========================================
   */

  function openInvestigation(
    alert: Alert,
  ) {
    if (
      alert.indicator_id ===
        null ||
      alert.indicator_id ===
        undefined
    ) {
      return;
    }

    navigate(
      `/investigations?indicator=${alert.indicator_id}`,
    );
  }

  /*
   * =========================================
   * SELECTED ALERT
   * =========================================
   */

  const selectedAlert =
    useMemo(
      () =>
        visibleAlerts.find(
          (alert) =>
            alert.id ===
            selectedAlertId,
        ) ?? null,
      [
        visibleAlerts,
        selectedAlertId,
      ],
    );

  return (
    <div className="alerts-page">
      {/* =================================
          PAGE HEADER
      ================================= */}

      <div className="alerts-page-header">
        <div>
          <div className="alerts-title-row">
            <Bell
              size={24}
              aria-hidden="true"
            />

            <h1>
              Security Alerts
            </h1>
          </div>

          <p>
            Monitor, investigate, and
            track security events across
            ThreatLens.
          </p>
        </div>

        <button
          type="button"
          className="refresh-button"
          onClick={
            refreshAlerts
          }
          disabled={
            loading ||
            refreshing
          }
          aria-label="Refresh alerts"
        >
          <RefreshCw
            size={16}
            className={
              refreshing
                ? "refresh-spinning"
                : ""
            }
          />

          {refreshing
            ? "Refreshing..."
            : "Refresh"}
        </button>
      </div>

      {/* =================================
          ALERT SUMMARY
      ================================= */}

      <div className="alerts-summary">
        <div className="alert-summary-card">
          <ShieldAlert
            size={20}
          />

          <div>
            <span>
              Total Alerts
            </span>

            <strong>
              {totalCount}
            </strong>
          </div>
        </div>

        <div className="alert-summary-card critical">
          <AlertTriangle
            size={20}
          />

          <div>
            <span>
              Critical
            </span>

            <strong>
              {criticalCount}
            </strong>
          </div>
        </div>

        <div className="alert-summary-card high">
          <AlertTriangle
            size={20}
          />

          <div>
            <span>
              High
            </span>

            <strong>
              {highCount}
            </strong>
          </div>
        </div>

        <div className="alert-summary-card">
          <Clock
            size={20}
          />

          <div>
            <span>
              Active
            </span>

            <strong>
              {openCount}
            </strong>
          </div>
        </div>

        <div className="alert-summary-card">
          <CheckCircle2
            size={20}
          />

          <div>
            <span>
              Resolved
            </span>

            <strong>
              {resolvedCount}
            </strong>
          </div>
        </div>
      </div>

      {/* =================================
          FILTERS
      ================================= */}

      <div className="alerts-filters">
        <div className="filter-heading">
          <Filter
            size={15}
            aria-hidden="true"
          />

          <span>
            Alert Filters
          </span>
        </div>

        <div className="filter-grid">
          {/* Search */}

          <div className="filter-input">
            <Search
              size={15}
              aria-hidden="true"
            />

            <input
              type="search"
              value={search}
              onChange={(event) =>
                setSearch(
                  event.target.value,
                )
              }
              placeholder="Search alerts..."
              aria-label="Search alerts"
            />

            {search && (
              <button
                type="button"
                className="filter-clear-icon"
                onClick={() =>
                  setSearch("")
                }
                aria-label="Clear alert search"
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Severity */}

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

          {/* Status */}

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
          </select>

          {/* Source */}

          <div className="filter-input">
            <input
              type="search"
              value={source}
              onChange={(event) =>
                setSource(
                  event.target.value,
                )
              }
              placeholder="Source..."
              aria-label="Filter by source"
            />

            {source && (
              <button
                type="button"
                className="filter-clear-icon"
                onClick={() =>
                  setSource("")
                }
                aria-label="Clear source filter"
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Clear */}

          {hasFilters && (
            <button
              type="button"
              className="clear-filters-button"
              onClick={
                clearFilters
              }
            >
              <X size={14} />

              Clear Filters
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
            <h3>
              Alert Queue
            </h3>

            <span>
              {visibleAlerts.length}{" "}
              alert
              {visibleAlerts.length ===
              1
                ? ""
                : "s"}{" "}
              displayed
            </span>
          </div>

          <div
            className="live-indicator"
            aria-label="Live alert monitoring"
          >
            <span className="live-dot" />

            Live
          </div>
        </div>

        {/* Loading */}

        {loading && (
          <div
            className="alerts-state"
            role="status"
            aria-live="polite"
          >
            <RefreshCw
              size={18}
              className="refresh-spinning"
            />

            <span>
              Loading alerts...
            </span>
          </div>
        )}

        {/* Error */}

        {!loading && error && (
          <div
            className="alerts-state error"
            role="alert"
          >
            <AlertTriangle
              size={18}
              aria-hidden="true"
            />

            <span>
              {error}
            </span>

            <button
              type="button"
              className="retry-button"
              onClick={() =>
                void loadAlerts(
                  {
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
                  },
                )
              }
            >
              Try Again
            </button>
          </div>
        )}

        {/* Empty */}

        {!loading &&
          !error &&
          visibleAlerts.length ===
            0 && (
            <div className="alerts-state">
              <ShieldAlert
                size={22}
                aria-hidden="true"
              />

              <span>
                {hasFilters
                  ? "No alerts match the selected filters."
                  : "No alerts available."}
              </span>

              {hasFilters && (
                <button
                  type="button"
                  className="retry-button"
                  onClick={
                    clearFilters
                  }
                >
                  Clear Filters
                </button>
              )}
            </div>
          )}

        {/* Alert Table */}

        {!loading &&
          !error &&
          visibleAlerts.length >
            0 && (
            <div className="alert-table-wrapper">
              <table className="alert-table">
                <caption className="sr-only">
                  ThreatLens security alerts
                </caption>

                <thead>
                  <tr>
                    <th scope="col">
                      Alert
                    </th>

                    <th scope="col">
                      Severity
                    </th>

                    <th scope="col">
                      Status
                    </th>

                    <th scope="col">
                      Source
                    </th>

                    <th scope="col">
                      Created
                    </th>

                    <th scope="col">
                      Investigation
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {visibleAlerts.map(
                    (alert) => {
                      const hasIndicator =
                        alert.indicator_id !==
                          null &&
                        alert.indicator_id !==
                          undefined;

                      const isSelected =
                        selectedAlertId ===
                        alert.id;

                      return (
                        <tr
                          key={
                            alert.id
                          }
                          className={
                            isSelected
                              ? "alert-row selected"
                              : "alert-row"
                          }
                          onClick={() =>
                            setSelectedAlertId(
                              isSelected
                                ? null
                                : alert.id,
                            )
                          }
                        >
                          {/* Alert */}

                          <td>
                            <div className="alert-title">
                              <strong>
                                {
                                  alert.title
                                }
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

                          {/* Severity */}

                          <td>
                            <span
                              className={severityClass(
                                alert.severity,
                              )}
                            >
                              {
                                alert.severity
                              }
                            </span>
                          </td>

                          {/* Status */}

                          <td>
                            <span
                              className={`status-badge ${statusClass(
                                alert.status,
                              )}`}
                            >
                              {formatStatus(
                                alert.status,
                              )}
                            </span>
                          </td>

                          {/* Source */}

                          <td>
                            <span className="source-text">
                              {alert.source ||
                                "Unknown"}
                            </span>
                          </td>

                          {/* Created */}

                          <td>
                            <span className="date-text">
                              {formatDate(
                                alert.created_at,
                              )}
                            </span>
                          </td>

                          {/* Investigation */}

                          <td>
                            {hasIndicator ? (
                              <button
                                type="button"
                                className="investigation-button"
                                onClick={(
                                  event,
                                ) => {
                                  event.stopPropagation();

                                  openInvestigation(
                                    alert,
                                  );
                                }}
                                aria-label={`Investigate alert ${alert.id}`}
                              >
                                <Search
                                  size={14}
                                  aria-hidden="true"
                                />

                                Investigate

                                <ChevronRight
                                  size={14}
                                  aria-hidden="true"
                                />
                              </button>
                            ) : (
                              <span className="no-investigation">
                                No IOC
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    },
                  )}
                </tbody>
              </table>
            </div>
          )}
      </div>

      {/* =================================
          SELECTED ALERT DETAILS
      ================================= */}

      {selectedAlert && (
        <div className="alert-selection">
          <div>
            <span>
              Selected Alert
            </span>

            <strong>
              {selectedAlert.title}
            </strong>
          </div>

          <div className="alert-selection-meta">
            <span
              className={severityClass(
                selectedAlert.severity,
              )}
            >
              {selectedAlert.severity}
            </span>

            <span
              className={`status-badge ${statusClass(
                selectedAlert.status,
              )}`}
            >
              {formatStatus(
                selectedAlert.status,
              )}
            </span>

            {selectedAlert.indicator_id !==
              null &&
              selectedAlert.indicator_id !==
                undefined && (
                <button
                  type="button"
                  className="investigation-button"
                  onClick={() =>
                    openInvestigation(
                      selectedAlert,
                    )
                  }
                >
                  <ExternalLink
                    size={14}
                    aria-hidden="true"
                  />

                  Open Investigation
                </button>
              )}
          </div>
        </div>
      )}
    </div>
  );
}

export default Alerts;