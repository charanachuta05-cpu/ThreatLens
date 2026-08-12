import { useEffect, useState } from "react";

import {
  AlertTriangle,
  Clock,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";

import {
  getAlerts,
  type Alert,
} from "../api/alerts";

import "./Alerts.css";

function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadAlerts() {
    try {
      setLoading(true);
      setError("");

      const data = await getAlerts({
        skip: 0,
        limit: 50,
      });

      setAlerts(data);
    } catch (err) {
      console.error("Failed to load alerts:", err);
      setError("Unable to load alerts.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAlerts();
  }, []);

  function formatDate(value: string) {
    return new Date(value).toLocaleString();
  }

  function severityClass(severity: string) {
    return `severity-badge ${severity.toLowerCase()}`;
  }

  return (
    <div className="alerts-page">
      <div className="page-heading">
        <div>
          <h2>Security Alerts</h2>

          <p>
            Monitor, review, and investigate detected
            security events.
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={loadAlerts}
          disabled={loading}
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      <div className="alerts-summary">
        <div className="alert-summary-card">
          <ShieldAlert size={20} />

          <div>
            <span>Total Alerts</span>
            <strong>{alerts.length}</strong>
          </div>
        </div>

        <div className="alert-summary-card critical">
          <AlertTriangle size={20} />

          <div>
            <span>Critical</span>
            <strong>
              {
                alerts.filter(
                  (alert) =>
                    alert.severity === "CRITICAL"
                ).length
              }
            </strong>
          </div>
        </div>

        <div className="alert-summary-card">
          <Clock size={20} />

          <div>
            <span>Open</span>
            <strong>
              {
                alerts.filter(
                  (alert) =>
                    alert.status === "OPEN"
                ).length
              }
            </strong>
          </div>
        </div>
      </div>

      <div className="alerts-card">
        <div className="alerts-card-header">
          <div>
            <h3>Alert Queue</h3>
            <span>
              Latest security events
            </span>
          </div>
        </div>

        {loading && (
          <div className="alerts-state">
            Loading alerts...
          </div>
        )}

        {!loading && error && (
          <div className="alerts-state error">
            {error}
          </div>
        )}

        {!loading &&
          !error &&
          alerts.length === 0 && (
            <div className="alerts-state">
              No alerts available.
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
                  {alerts.map((alert) => (
                    <tr key={alert.id}>
                      <td>
                        <div className="alert-title">
                          <strong>
                            {alert.title}
                          </strong>

                          {alert.description && (
                            <span>
                              {alert.description}
                            </span>
                          )}
                        </div>
                      </td>

                      <td>
                        <span
                          className={severityClass(
                            alert.severity
                          )}
                        >
                          {alert.severity}
                        </span>
                      </td>

                      <td>
                        <span className="status-badge">
                          {alert.status}
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
                            alert.created_at
                          )}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </div>
    </div>
  );
}

export default Alerts;