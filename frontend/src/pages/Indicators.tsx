import { useEffect, useState } from "react";

import {
  Activity,
  Filter,
  RefreshCw,
  Search,
  ShieldAlert,
} from "lucide-react";

import {
  getIndicators,
  type Indicator,
} from "../api/indicators";

import "./Indicators.css";

function Indicators() {
  const [indicators, setIndicators] = useState<Indicator[]>(
    [],
  );

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");

  async function loadIndicators() {
    try {
      setLoading(true);
      setError("");

      const data = await getIndicators({
        skip: 0,
        limit: 50,
        search: search.trim() || undefined,
        severity: severity || undefined,
      });

      setIndicators(data);
    } catch (err) {
      console.error(
        "Failed to load indicators:",
        err,
      );

      setError(
        "Unable to load threat indicators.",
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadIndicators();
  }, [search, severity]);

  const highRiskCount = indicators.filter(
    (indicator) =>
      indicator.severity === "HIGH" ||
      indicator.severity === "CRITICAL",
  ).length;

  const averageThreatScore =
    indicators.length > 0
      ? Math.round(
          indicators.reduce(
            (total, indicator) =>
              total + indicator.threat_score,
            0,
          ) / indicators.length,
        )
      : 0;

  return (
    <div className="indicators-page">
      <div className="page-heading">
        <div>
          <h2>Threat Indicators</h2>

          <p>
            Monitor and analyze indicators of
            compromise detected by ThreatLens.
          </p>
        </div>

        <button
          type="button"
          className="refresh-button"
          onClick={loadIndicators}
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

      <div className="indicator-summary">
        <div className="indicator-summary-card">
          <ShieldAlert size={20} />

          <div>
            <span>Total Indicators</span>

            <strong>
              {indicators.length}
            </strong>
          </div>
        </div>

        <div className="indicator-summary-card critical">
          <Activity size={20} />

          <div>
            <span>High Risk</span>

            <strong>
              {highRiskCount}
            </strong>
          </div>
        </div>

        <div className="indicator-summary-card">
          <Activity size={20} />

          <div>
            <span>Average Threat Score</span>

            <strong>
              {averageThreatScore}
            </strong>
          </div>
        </div>
      </div>

      <div className="indicator-card">
        <div className="indicator-toolbar">
          <div className="search-box">
            <Search size={16} />

            <input
              type="search"
              placeholder="Search indicator..."
              value={search}
              onChange={(event) =>
                setSearch(event.target.value)
              }
              aria-label="Search indicators"
            />
          </div>

          <div className="filter-box">
            <Filter size={15} />

            <select
              value={severity}
              onChange={(event) =>
                setSeverity(event.target.value)
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
          </div>
        </div>

        {loading && (
          <div className="indicator-state">
            Loading indicators...
          </div>
        )}

        {!loading && error && (
          <div className="indicator-state error">
            {error}

            <button
              type="button"
              onClick={loadIndicators}
              className="retry-button"
            >
              Try Again
            </button>
          </div>
        )}

        {!loading &&
          !error &&
          indicators.length === 0 && (
            <div className="indicator-state">
              No indicators found.
            </div>
          )}

        {!loading &&
          !error &&
          indicators.length > 0 && (
            <div className="indicator-table-wrapper">
              <table className="indicator-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Indicator</th>
                    <th>Severity</th>
                    <th>Threat</th>
                    <th>Reputation</th>
                    <th>Confidence</th>
                    <th>Tags</th>
                  </tr>
                </thead>

                <tbody>
                  {indicators.map(
                    (indicator) => (
                      <tr key={indicator.id}>
                        <td>
                          <span className="type-badge">
                            {
                              indicator.indicator_type
                            }
                          </span>
                        </td>

                        <td>
                          <div className="indicator-value-cell">
                            <strong
                              title={
                                indicator.value
                              }
                            >
                              {indicator.value}
                            </strong>

                            <span>
                              {indicator.source}
                            </span>
                          </div>
                        </td>

                        <td>
                          <span
                            className={`severity-badge ${indicator.severity.toLowerCase()}`}
                          >
                            {
                              indicator.severity
                            }
                          </span>
                        </td>

                        <td>
                          <span className="score">
                            {
                              indicator.threat_score
                            }
                          </span>
                        </td>

                        <td>
                          <span className="score">
                            {
                              indicator.reputation_score
                            }
                          </span>
                        </td>

                        <td>
                          <span className="score">
                            {
                              indicator.confidence_score
                            }
                          </span>
                        </td>

                        <td>
                          <div className="tag-list">
                            {indicator.tags.length >
                            0 ? (
                              indicator.tags.map(
                                (tag) => (
                                  <span
                                    className="tag"
                                    key={tag}
                                  >
                                    {tag}
                                  </span>
                                ),
                              )
                            ) : (
                              <span className="no-tags">
                                —
                              </span>
                            )}
                          </div>
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

export default Indicators;