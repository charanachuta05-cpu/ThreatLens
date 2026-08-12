import {
  useEffect,
  useState,
} from "react";

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
  const [indicators, setIndicators] =
    useState<Indicator[]>([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const [search, setSearch] =
    useState("");

  const [severity, setSeverity] =
    useState("");

  async function loadIndicators(
    searchValue = search,
    severityValue = severity,
  ) {
    try {
      setLoading(true);
      setError("");

      const data = await getIndicators({
        skip: 0,
        limit: 50,
        search:
          searchValue.trim() || undefined,
        severity:
          severityValue || undefined,
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
    let cancelled = false;

    async function fetchIndicators() {
      try {
        setLoading(true);
        setError("");

        const data = await getIndicators({
          skip: 0,
          limit: 50,
          search:
            search.trim() || undefined,
          severity:
            severity || undefined,
        });

        if (cancelled) {
          return;
        }

        setIndicators(data);
      } catch (err) {
        if (cancelled) {
          return;
        }

        console.error(
          "Failed to load indicators:",
          err,
        );

        setError(
          "Unable to load threat indicators.",
        );
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void fetchIndicators();

    return () => {
      cancelled = true;
    };
  }, [search, severity]);

  const highRiskCount =
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

  return (
    <div className="indicators-page">
      <div className="page-heading">
        <div>
          <h2>Threat Indicators</h2>

          <p>
            Monitor and analyze indicators
            of compromise detected by
            ThreatLens.
          </p>
        </div>

        <button
          type="button"
          className="refresh-button"
          onClick={() =>
            void loadIndicators()
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

      <div className="indicator-summary">
        <div className="indicator-summary-card">
          <ShieldAlert size={20} />

          <div>
            <span>
              Total Indicators
            </span>

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
            <span>
              Average Threat Score
            </span>

            <strong>
              {averageThreatScore}
            </strong>
          </div>
        </div>
      </div>

      <div className="indicators-card">
        <div className="indicator-filters">
          <div className="search-field">
            <Search size={16} />

            <input
              type="text"
              value={search}
              onChange={(event) =>
                setSearch(
                  event.target.value,
                )
              }
              placeholder="Search indicators..."
              aria-label="Search indicators"
            />
          </div>

          <div className="severity-field">
            <Filter size={16} />

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
          </div>
        </div>

        {loading && (
          <div className="indicators-state">
            Loading threat indicators...
          </div>
        )}

        {!loading && error && (
          <div className="indicators-state error">
            {error}

            <button
              type="button"
              onClick={() =>
                void loadIndicators()
              }
              className="retry-button"
            >
              Try Again
            </button>
          </div>
        )}

        {!loading &&
          !error &&
          indicators.length === 0 && (
            <div className="indicators-state">
              No threat indicators found.
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
                    <th>Threat Score</th>
                    <th>Reputation</th>
                    <th>Source</th>
                    <th>Created</th>
                  </tr>
                </thead>

                <tbody>
                  {indicators.map(
                    (indicator) => (
                      <tr
                        key={indicator.id}
                      >
                        <td>
                          {indicator.indicator_type}
                        </td>

                        <td>
                          <strong>
                            {indicator.value}
                          </strong>
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
                          {indicator.threat_score}
                        </td>

                        <td>
                          {
                            indicator.reputation_score
                          }
                        </td>

                        <td>
                          {indicator.source ||
                            "Unknown"}
                        </td>

                        <td>
                          {new Date(
                            indicator.created_at,
                          ).toLocaleString()}
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
