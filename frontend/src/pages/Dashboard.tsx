import { useEffect, useState } from "react";

import {
  Activity,
  AlertTriangle,
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

  useEffect(() => {
    async function loadDashboard() {
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
          err
        );

        setError(
          "Unable to load dashboard data."
        );
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, []);

  function formatDate(
    value: string
  ) {
    return new Date(
      value
    ).toLocaleString();
  }

  if (loading) {
    return (
      <div className="dashboard-state">
        Loading ThreatLens dashboard...
      </div>
    );
  }

  if (error) {
    return (
      <div className="dashboard-state dashboard-error">
        <AlertTriangle size={20} />
        <span>{error}</span>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="dashboard-state">
        No dashboard data available.
      </div>
    );
  }

  return (
    <div className="dashboard-page">

      <div className="page-heading">
        <div>
          <h2>
            Security Operations Dashboard
          </h2>

          <p>
            Real-time overview of ThreatLens
            threat intelligence activity.
          </p>
        </div>

        <div className="engine-status">
          <span />
          Threat Intelligence Engine Online
        </div>
      </div>

      <div className="stats-grid">

        <div className="stat-card">
          <div className="stat-icon">
            <Target size={20} />
          </div>

          <div>
            <span>Total Indicators</span>
            <strong>
              {summary.total_indicators}
            </strong>
          </div>
        </div>

        <div className="stat-card critical">
          <div className="stat-icon">
            <ShieldAlert size={20} />
          </div>

          <div>
            <span>Critical Indicators</span>
            <strong>
              {summary.critical_indicators}
            </strong>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">
            <AlertTriangle size={20} />
          </div>

          <div>
            <span>High Indicators</span>
            <strong>
              {summary.high_indicators}
            </strong>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">
            <Activity size={20} />
          </div>

          <div>
            <span>Active Alerts</span>
            <strong>
              {summary.active_alerts}
            </strong>
          </div>
        </div>

      </div>

      <div className="dashboard-grid">

        {/* Recent Alerts */}

        <div className="dashboard-card">

          <div className="card-header">
            <h3>Recent Alerts</h3>
            <span>Latest 5</span>
          </div>

          {alerts.length === 0 ? (
            <div className="empty-state">
              No alerts available.
            </div>
          ) : (
            <div className="alert-list">

              {alerts.map((alert) => (
                <div
                  className="alert-row"
                  key={alert.id}
                >

                  <div className="alert-main">

                    <strong>
                      {alert.title}
                    </strong>

                    <span>
                      {alert.source ||
                        "Unknown source"}
                    </span>

                  </div>

                  <div className="alert-meta">

                    <span
                      className={`severity-badge ${alert.severity.toLowerCase()}`}
                    >
                      {alert.severity}
                    </span>

                    <span className="alert-status">
                      {alert.status}
                    </span>

                    <small>
                      {formatDate(
                        alert.created_at
                      )}
                    </small>

                  </div>

                </div>
              ))}

            </div>
          )}

        </div>

        {/* IOC Monitoring */}

        <div className="dashboard-card">

          <div className="card-header">
            <h3>IOC Monitoring</h3>
            <span>Latest 5</span>
          </div>

          {indicators.length === 0 ? (
            <div className="empty-state">
              No indicators available.
            </div>
          ) : (
            <div className="indicator-list">

              {indicators.map(
                (indicator) => (
                  <div
                    className="indicator-row"
                    key={indicator.id}
                  >

                    <div className="indicator-main">

                      <span className="indicator-type">
                        {indicator.indicator_type}
                      </span>

                      <span className="indicator-value">
                        {indicator.value}
                      </span>

                    </div>

                    <div className="indicator-meta">

                      <span
                        className={`severity-badge ${indicator.severity.toLowerCase()}`}
                      >
                        {indicator.severity}
                      </span>

                      <strong>
                        {indicator.threat_score}
                      </strong>

                    </div>

                  </div>
                )
              )}

            </div>
          )}

        </div>

      </div>

      <div className="dashboard-grid">

        <div className="dashboard-card">

          <div className="card-header">
            <h3>Threat Score</h3>
            <span>Current average</span>
          </div>

          <div className="score-highlight">
            <strong>
              {summary.average_threat_score}
            </strong>

            <span>
              Average Threat Score
            </span>
          </div>

        </div>

        <div className="dashboard-card">

          <div className="card-header">
            <h3>Severity Overview</h3>
            <span>Current indicators</span>
          </div>

          <div className="severity-list">

            <div>
              <span>Critical</span>
              <strong>
                {summary.critical_indicators}
              </strong>
            </div>

            <div>
              <span>High</span>
              <strong>
                {summary.high_indicators}
              </strong>
            </div>

            <div>
              <span>Total</span>
              <strong>
                {summary.total_indicators}
              </strong>
            </div>

          </div>

        </div>

      </div>

    </div>
  );
}

export default Dashboard;