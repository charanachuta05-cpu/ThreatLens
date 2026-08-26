import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Bell,
  CalendarDays,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  Globe2,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Target,
  TrendingUp,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";

import apiClient from "../api/client";
import "./Dashboard.css";

interface DashboardAlertTrendPoint {
  date: string;
  total: number;
  high: number;
  critical: number;
}

interface DashboardSummary {
  total_indicators: number;
  critical_indicators: number;
  high_indicators: number;
  active_alerts: number;
  critical_alerts: number;
  average_threat_score: number;
  alert_trend: DashboardAlertTrendPoint[];

  recent_alerts?: DashboardAlert[];
  recent_indicators?: DashboardIndicator[];
}

interface DashboardAlert {
  id: number;
  title: string;
  description?: string | null;
  severity: string;
  status: string;
  source?: string | null;
  created_at: string;
  indicator_id?: number | null;
}

interface DashboardIndicator {
  id: number;
  indicator_type: string;
  value: string;
  severity: string;
  threat_score: number;
  reputation_score?: number;
  confidence_score?: number;
  source?: string | null;
  created_at: string;
}

interface Metric {
  label: string;
  value: number;
  icon: typeof Shield;
  tone: string;
  change?: string;
  changeTone?: "up" | "down" | "neutral";
}

const EMPTY_SUMMARY: DashboardSummary = {
  total_indicators: 0,
  critical_indicators: 0,
  high_indicators: 0,
  active_alerts: 0,
  critical_alerts: 0,
  average_threat_score: 0,
  alert_trend: [],
};

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

function formatDate(value: string | null | undefined): string {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return date.toLocaleString([], {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatTime(value: string | null | undefined): string {
  if (!value) {
    return "--:--";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "--:--";
  }

  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
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

function severityTone(
  severity: string | null | undefined,
): "critical" | "high" | "medium" | "low" {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return "critical";

    case "HIGH":
      return "high";

    case "MEDIUM":
      return "medium";

    default:
      return "low";
  }
}

function getApiErrorMessage(error: unknown): string {
  if (!axios.isAxiosError(error)) {
    return "Unable to load dashboard data.";
  }

  switch (error.response?.status) {
    case 401:
      return "Your session has expired. Please log in again.";

    case 403:
      return "You do not have permission to view the dashboard.";

    default:
      return "Unable to load dashboard data.";
  }
}

function Dashboard() {
  const [summary, setSummary] =
    useState<DashboardSummary>(EMPTY_SUMMARY);

  const [alerts, setAlerts] =
    useState<DashboardAlert[]>([]);

  const [indicators, setIndicators] =
    useState<DashboardIndicator[]>([]);

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState("");

  const [lastUpdated, setLastUpdated] =
    useState(new Date());

  const loadDashboard = useCallback(
    async (background = false) => {
      try {
        if (background) {
          setRefreshing(true);
        } else {
          setLoading(true);
        }

        setError("");

        const [
          summaryResponse,
          alertsResponse,
          indicatorsResponse,
        ] = await Promise.all([
          apiClient.get<DashboardSummary>(
            "/dashboard/summary",
          ),

          apiClient.get<DashboardAlert[]>(
            "/alerts/",
            {
              params: {
                skip: 0,
                limit: 50,
              },
            },
          ),

          apiClient.get<DashboardIndicator[]>(
            "/indicators/",
            {
              params: {
                skip: 0,
                limit: 100,
                sort_by: "created_at",
                order: "desc",
              },
            },
          ),
        ]);

        setSummary({
          ...EMPTY_SUMMARY,
          ...summaryResponse.data,
        });

        setAlerts(
          Array.isArray(alertsResponse.data)
            ? alertsResponse.data
            : [],
        );

        setIndicators(
          Array.isArray(indicatorsResponse.data)
            ? indicatorsResponse.data
            : [],
        );

        setLastUpdated(new Date());
      } catch (requestError) {
        console.error(
          "Failed to load dashboard:",
          requestError,
        );

        setError(
          getApiErrorMessage(requestError),
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadDashboard();
    }, 0);

    return () => {
      window.clearTimeout(timer);
    };
  }, [loadDashboard]);

  const recentAlerts = useMemo(
    () =>
      alerts
        .slice()
        .sort(
          (a, b) =>
            new Date(b.created_at).getTime() -
            new Date(a.created_at).getTime(),
        )
        .slice(0, 5),
    [alerts],
  );

  const recentIndicators = useMemo(
    () =>
      indicators
        .slice()
        .sort(
          (a, b) =>
            new Date(b.created_at).getTime() -
            new Date(a.created_at).getTime(),
        )
        .slice(0, 6),
    [indicators],
  );

  const severityCounts = useMemo(() => {
    const counts = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };

    alerts.forEach((alert) => {
      const severity =
        alert.severity?.toUpperCase();

      if (severity in counts) {
        counts[
          severity as keyof typeof counts
        ] += 1;
      }
    });

    return counts;
  }, [alerts]);

  const totalSeverityAlerts =
    Object.values(severityCounts).reduce(
      (total, value) => total + value,
      0,
    );

  const severityPercent = (
    value: number,
  ): number =>
    totalSeverityAlerts === 0
      ? 0
      : Math.round(
          (value / totalSeverityAlerts) * 100,
        );

  const indicatorTypes = useMemo(() => {
    const counts = new Map<string, number>();

    indicators.forEach((indicator) => {
      const type =
        indicator.indicator_type || "UNKNOWN";

      counts.set(
        type,
        (counts.get(type) ?? 0) + 1,
      );
    });

    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [indicators]);

  const maxIndicatorType =
    indicatorTypes[0]?.[1] ?? 1;

  const alertTrend = summary.alert_trend;

  const maxTrend =
    Math.max(
      ...alertTrend.map(
        (point) => point.total,
      ),
      1,
    );

  const metrics: Metric[] = [
    {
      label: "Active Alerts",
      value: summary.active_alerts,
      icon: ShieldAlert,
      tone: "red",
      change: "Open + in-progress",
      changeTone: summary.active_alerts > 0 ? "up" : "neutral",
    },
    {
      label: "Critical Alerts",
      value: summary.critical_alerts,
      icon: AlertTriangle,
      tone: "orange",
      change:
        summary.critical_alerts > 0
          ? "Immediate attention"
          : "No critical alerts",
      changeTone:
        summary.critical_alerts > 0
          ? "up"
          : "neutral",
    },
    {
      label: "Threat Indicators",
      value: summary.total_indicators,
      icon: Activity,
      tone: "purple",
      change: "Intelligence inventory",
      changeTone: "neutral",
    },
    {
      label: "Critical Indicators",
      value: summary.critical_indicators,
      icon: Target,
      tone: "yellow",
      change:
        summary.critical_indicators > 0
          ? "High-priority intelligence"
          : "No critical indicators",
      changeTone:
        summary.critical_indicators > 0
          ? "up"
          : "neutral",
    },
    {
      label: "High-Risk Indicators",
      value: summary.high_indicators,
      icon: Target,
      tone: "blue",
      change:
        summary.high_indicators > 0
          ? "Requires analyst review"
          : "No high-risk indicators",
      changeTone:
        summary.high_indicators > 0
          ? "up"
          : "neutral",
    },
    {
      label: "Average Threat Score",
      value: summary.average_threat_score,
      icon: TrendingUp,
      tone: "green",
      change:
        summary.average_threat_score >= 70
          ? "Elevated risk posture"
          : "Within monitored range",
      changeTone:
        summary.average_threat_score >= 70
          ? "up"
          : "neutral",
    },
  ];

  const dateLabel =
    lastUpdated.toLocaleDateString([], {
      day: "2-digit",
      month: "short",
      year: "numeric",
    });

  const timeLabel =
    lastUpdated.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });

  return (
    <main className="dashboard-page">
      <div className="dashboard-shell">
        {/* =========================================
            HEADER
        ========================================= */}

        <header className="dashboard-header">
          <div>
            <div className="dashboard-eyebrow">
              <span className="live-dot" />
              SECURITY OPERATIONS CENTER
            </div>

            <h1>Security Dashboard</h1>

            <p>
              Overview of your security posture
              and threat landscape.
            </p>
          </div>

          <div className="dashboard-header-actions">
            <div className="dashboard-date">
              <CalendarDays size={16} />

              <div>
                <strong>{dateLabel}</strong>
                <span>{timeLabel}</span>
              </div>
            </div>

            <button
              type="button"
              className="dashboard-refresh"
              onClick={() =>
                void loadDashboard(true)
              }
              disabled={refreshing}
            >
              <RefreshCw
                size={16}
                className={
                  refreshing
                    ? "spin"
                    : undefined
                }
              />
              Refresh
            </button>

            <button
              type="button"
              className="dashboard-icon-button"
              aria-label="Notifications"
            >
              <Bell size={18} />
              <span className="notification-badge">
                {summary.critical_alerts}
              </span>
            </button>
          </div>
        </header>

        {/* =========================================
            ERROR
        ========================================= */}

        {error && (
          <div className="dashboard-error">
            <CircleAlert size={18} />
            <span>{error}</span>

            <button
              type="button"
              onClick={() =>
                void loadDashboard()
              }
            >
              Retry
            </button>
          </div>
        )}

        {/* =========================================
            TOP METRICS
        ========================================= */}

        <section className="metric-grid">
          {metrics.map((metric) => {
            const Icon = metric.icon;

            return (
              <article
                className={`metric-card metric-${metric.tone}`}
                key={metric.label}
              >
                <div className="metric-icon">
                  <Icon size={21} />
                </div>

                <div className="metric-content">
                  <span className="metric-label">
                    {metric.label}
                  </span>

                  <strong className="metric-value">
                    {loading
                      ? "—"
                      : formatNumber(
                          metric.value,
                        )}
                  </strong>

                  <span
                    className={`metric-change ${metric.changeTone ?? "neutral"}`}
                  >
                    {metric.changeTone ===
                      "up" && (
                      <ArrowUpRight
                        size={14}
                      />
                    )}

                    {metric.changeTone ===
                      "down" && (
                      <ArrowDownRight
                        size={14}
                      />
                    )}

                    {metric.change}
                  </span>
                </div>
              </article>
            );
          })}
        </section>

        {/* =========================================
            ANALYTICS ROW
        ========================================= */}

        <section className="dashboard-grid dashboard-grid-top">
          {/* ALERT TREND */}

          <article className="dashboard-card alert-trend-card">
            <div className="card-header">
              <div>
                <h2>Alerts Over Time</h2>
                <p>
                  Last 7 days of observed security
                  events
                </p>
              </div>

              <button
                type="button"
                className="period-selector"
              >
                7 Days
                <ChevronDown size={15} />
              </button>
            </div>

            <div className="chart-legend">
              <span>
                <i className="legend-blue" />
                Total Alerts
              </span>

              <span>
                <i className="legend-red" />
                High Severity
              </span>

              <span>
                <i className="legend-orange" />
                Critical
              </span>
            </div>

            <div className="trend-chart">
              <div className="chart-y-axis">
                <span>{maxTrend}</span>
                <span>
                  {Math.round(
                    maxTrend * 0.75,
                  )}
                </span>
                <span>
                  {Math.round(
                    maxTrend * 0.5,
                  )}
                </span>
                <span>
                  {Math.round(
                    maxTrend * 0.25,
                  )}
                </span>
                <span>0</span>
              </div>

              <div className="chart-area">
                <div className="chart-grid-lines">
                  <span />
                  <span />
                  <span />
                  <span />
                  <span />
                </div>

                <div className="trend-bars">
                  {alertTrend.map(
                    (point) => (
                      <div
                        className="trend-column"
                        key={point.date}
                      >
                        <div className="trend-bar-wrap">
                          <div
                            className="trend-bar total"
                            style={{
                              height: `${
                                (point.total /
                                  maxTrend) *
                                100
                              }%`,
                            }}
                            title={`${point.total} alerts`}
                          />

                          <div
                            className="trend-bar high"
                            style={{
                              height: `${
                                (point.high /
                                  maxTrend) *
                                100
                              }%`,
                            }}
                          />

                          <div
                            className="trend-bar critical"
                            style={{
                              height: `${
                                (point.critical /
                                  maxTrend) *
                                100
                              }%`,
                            }}
                          />
                        </div>

                        <span>
                          {new Date(`${point.date}T00:00:00`).toLocaleDateString(
                            [],
                            {
                              day: "2-digit",
                              month: "short",
                            },
                          )}
                        </span>
                      </div>
                    ),
                  )}
                </div>
              </div>
            </div>
          </article>

          {/* SEVERITY */}

          <article className="dashboard-card severity-card">
            <div className="card-header">
              <div>
                <h2>Alerts by Severity</h2>
                <p>
                  Distribution of loaded alerts
                </p>
              </div>

              <div className="severity-status">
                <span className="live-dot" />
                Live
              </div>
            </div>

            <div className="severity-layout">
              <div
                className="severity-donut"
                style={{
                  background: `conic-gradient(
                    #ef4444 0 ${
                      severityPercent(
                        severityCounts.CRITICAL,
                      ) +
                      severityPercent(
                        severityCounts.HIGH,
                      )
                    }%,
                    #f97316 ${
                      severityPercent(
                        severityCounts.CRITICAL,
                      ) +
                      severityPercent(
                        severityCounts.HIGH,
                      )
                    }% ${
                      severityPercent(
                        severityCounts.CRITICAL,
                      ) +
                      severityPercent(
                        severityCounts.HIGH,
                      ) +
                      severityPercent(
                        severityCounts.MEDIUM,
                      )
                    }%,
                    #eab308 ${
                      severityPercent(
                        severityCounts.CRITICAL,
                      ) +
                      severityPercent(
                        severityCounts.HIGH,
                      ) +
                      severityPercent(
                        severityCounts.MEDIUM,
                      )
                    }% 100%
                  )`,
                }}
              >
                <div>
                  <strong>
                    {formatNumber(
                      totalSeverityAlerts,
                    )}
                  </strong>

                  <span>Total</span>
                </div>
              </div>

              <div className="severity-list">
                {[
                  {
                    label: "Critical",
                    value:
                      severityCounts.CRITICAL,
                    className:
                      "severity-critical-dot",
                  },
                  {
                    label: "High",
                    value:
                      severityCounts.HIGH,
                    className:
                      "severity-high-dot",
                  },
                  {
                    label: "Medium",
                    value:
                      severityCounts.MEDIUM,
                    className:
                      "severity-medium-dot",
                  },
                  {
                    label: "Low",
                    value:
                      severityCounts.LOW,
                    className:
                      "severity-low-dot",
                  },
                ].map((item) => (
                  <div
                    className="severity-list-row"
                    key={item.label}
                  >
                    <span>
                      <i
                        className={
                          item.className
                        }
                      />
                      {item.label}
                    </span>

                    <strong>
                      {formatNumber(
                        item.value,
                      )}
                    </strong>

                    <small>
                      {severityPercent(
                        item.value,
                      )}
                      %
                    </small>
                  </div>
                ))}
              </div>
            </div>
          </article>

          {/* TOP TYPES */}

          <article className="dashboard-card indicator-types-card">
            <div className="card-header">
              <div>
                <h2>Top Indicator Types</h2>
                <p>By intelligence volume</p>
              </div>
            </div>

            <div className="indicator-type-list">
              {indicatorTypes.length === 0 ? (
                <div className="empty-state">
                  No indicators available.
                </div>
              ) : (
                indicatorTypes.map(
                  ([type, count], index) => (
                    <div
                      className="indicator-type-row"
                      key={type}
                    >
                      <div className="type-icon">
                        {type
                          .toUpperCase()
                          .includes("IP") ? (
                          <Globe2
                            size={16}
                          />
                        ) : type
                            .toUpperCase()
                            .includes(
                              "URL",
                            ) ? (
                          <Search
                            size={16}
                          />
                        ) : (
                          <Zap size={16} />
                        )}
                      </div>

                      <div className="type-main">
                        <div>
                          <span>
                            {type}
                          </span>

                          <strong>
                            {formatNumber(
                              count,
                            )}
                          </strong>
                        </div>

                        <div className="type-progress">
                          <span
                            style={{
                              width: `${
                                (count /
                                  maxIndicatorType) *
                                100
                              }%`,
                            }}
                            className={`type-progress-${index}`}
                          />
                        </div>
                      </div>
                    </div>
                  ),
                )
              )}
            </div>

            <button
              type="button"
              className="card-link"
              onClick={() => {
                window.location.href =
                  "/indicators";
              }}
            >
              View all indicators
              <ArrowRight size={15} />
            </button>
          </article>
        </section>

        {/* =========================================
            LOWER ROW
        ========================================= */}

        <section className="dashboard-grid dashboard-grid-bottom">
          {/* RECENT ALERTS */}

          <article className="dashboard-card recent-alerts-card">
            <div className="card-header">
              <div>
                <h2>Recent Security Alerts</h2>
                <p>
                  Latest detected events requiring
                  analyst attention
                </p>
              </div>

              <button
                type="button"
                className="card-outline-button"
                onClick={() => {
                  window.location.href =
                    "/alerts";
                }}
              >
                View All
                <ArrowRight size={14} />
              </button>
            </div>

            <div className="alert-list">
              {recentAlerts.length === 0 ? (
                <div className="empty-state">
                  <CheckCircle2
                    size={24}
                  />
                  No recent alerts.
                </div>
              ) : (
                recentAlerts.map((alert) => {
                  const tone =
                    severityTone(
                      alert.severity,
                    );

                  return (
                    <div
                      className="recent-alert-row"
                      key={alert.id}
                    >
                      <div
                        className={`alert-severity-icon ${tone}`}
                      >
                        {tone ===
                        "critical" ? (
                          <AlertTriangle
                            size={16}
                          />
                        ) : (
                          <ShieldAlert
                            size={16}
                          />
                        )}
                      </div>

                      <div className="recent-alert-main">
                        <div className="recent-alert-title">
                          <strong>
                            {alert.title}
                          </strong>

                          <span
                            className={`severity-pill ${severityClass(
                              alert.severity,
                            )}`}
                          >
                            {alert.severity}
                          </span>
                        </div>

                        <span className="recent-alert-meta">
                          {alert.source ||
                            "Threat Intelligence"}
                          {" · "}
                          {alert.status}
                        </span>
                      </div>

                      <time>
                        {formatTime(
                          alert.created_at,
                        )}
                      </time>

                      <span className="alert-live-dot" />
                    </div>
                  );
                })
              )}
            </div>
          </article>

          {/* THREAT POSTURE */}

          <article className="dashboard-card posture-card">
            <div className="card-header">
              <div>
                <h2>Threat Posture</h2>
                <p>
                  Current intelligence risk profile
                </p>
              </div>

              <div className="posture-score">
                <span>
                  Overall
                </span>
                <strong>
                  {summary.average_threat_score}
                </strong>
                <small>/100</small>
              </div>
            </div>

            <div className="posture-visual">
              <div className="radar-ring ring-one" />
              <div className="radar-ring ring-two" />
              <div className="radar-ring ring-three" />

              <div className="radar-cross horizontal" />
              <div className="radar-cross vertical" />

              <div className="radar-core">
                <Shield size={28} />
                <span>
                  {summary.average_threat_score >=
                  70
                    ? "ELEVATED"
                    : "MONITORED"}
                </span>
              </div>

              <div className="radar-point point-one" />
              <div className="radar-point point-two" />
              <div className="radar-point point-three" />
            </div>

            <div className="posture-breakdown">
              <div>
                <span>
                  <i className="posture-red" />
                  High risk
                </span>
                <strong>
                  {
                    summary.high_indicators
                  }
                </strong>
              </div>

              <div>
                <span>
                  <i className="posture-orange" />
                  Critical
                </span>
                <strong>
                  {summary.critical_alerts}
                </strong>
              </div>

              <div>
                <span>
                  <i className="posture-green" />
                  Avg score
                </span>
                <strong>
                  {summary.average_threat_score}
                </strong>
              </div>
            </div>
          </article>

          {/* RECENT INTELLIGENCE */}

          <article className="dashboard-card intelligence-card">
            <div className="card-header">
              <div>
                <h2>Latest Intelligence</h2>
                <p>
                  Highest priority indicators
                </p>
              </div>
            </div>

            <div className="intelligence-list">
              {recentIndicators.length ===
              0 ? (
                <div className="empty-state">
                  No indicators available.
                </div>
              ) : (
                recentIndicators.map(
                  (indicator) => (
                    <div
                      className="intelligence-row"
                      key={indicator.id}
                    >
                      <div
                        className={`intelligence-type ${severityTone(
                          indicator.severity,
                        )}`}
                      >
                        {indicator.indicator_type
                          .slice(0, 3)
                          .toUpperCase()}
                      </div>

                      <div className="intelligence-main">
                        <strong>
                          {indicator.value}
                        </strong>

                        <span>
                          {indicator.source ||
                            "Threat Intelligence"}
                        </span>
                      </div>

                      <div className="intelligence-score">
                        <span>
                          Score
                        </span>

                        <strong>
                          {indicator.threat_score}
                        </strong>
                      </div>
                    </div>
                  ),
                )
              )}
            </div>
          </article>
        </section>

        {/* =========================================
            BOTTOM INTELLIGENCE BAR
        ========================================= */}

        <section className="intelligence-summary-bar">
          <div className="summary-brand">
            <div className="summary-brand-icon">
              <Shield size={18} />
            </div>

            <div>
              <strong>
                Threat Intelligence Summary
              </strong>

              <span>
                Operational intelligence at a glance
              </span>
            </div>
          </div>

          <div className="summary-stat">
            <Activity size={18} />
            <div>
              <strong>
                {formatNumber(
                  summary.total_indicators
                )}
              </strong>
              <span>
                Total Indicators
              </span>
            </div>
          </div>

          <div className="summary-stat">
            <Target size={18} />
            <div>
              <strong>
                {formatNumber(
                  summary.high_indicators,
                )}
              </strong>
              <span>
                High Risk
              </span>
            </div>
          </div>

          <div className="summary-stat">
            <AlertTriangle size={18} />
            <div>
              <strong>
                {formatNumber(
                  summary.critical_alerts,
                )}
              </strong>
              <span>
                Critical Alerts
              </span>
            </div>
          </div>

          <div className="summary-stat">
            <TrendingUp size={18} />
            <div>
              <strong>
                {summary.average_threat_score}
              </strong>
              <span>
                Avg Threat Score
              </span>
            </div>
          </div>

          <div className="summary-status">
            <span className="status-pulse" />
            <div>
              <strong>
                Monitoring Active
              </strong>
              <span>
                Last updated {formatDate(
                  lastUpdated.toISOString(),
                )}
              </span>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}

export default Dashboard;
