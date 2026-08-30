import {
  Activity,
  AlertTriangle,
  ArrowRight,
  GitBranch,
  Search,
  ShieldCheck,
  Siren,
} from "lucide-react";
import {
  useState,
} from "react";
import type { FormEvent } from "react";

import {
  getCorrelation,
  type CorrelationResponse,
} from "../api/correlation";

import {
  createIncident,
} from "../api/incidents";

import "./Correlation.css";


function correlationLevel(
  score: number,
): string {
  if (score >= 80) {
    return "Strong";
  }

  if (score >= 60) {
    return "Related";
  }

  return "Weak";
}


function Correlation() {
  const [
    indicatorId,
    setIndicatorId,
  ] = useState("");

  const [
    result,
    setResult,
  ] = useState<CorrelationResponse | null>(
    null,
  );

  const [
    loading,
    setLoading,
  ] = useState(false);

  const [
    error,
    setError,
  ] = useState<string | null>(null);

  const [
    creatingIncident,
    setCreatingIncident,
  ] = useState(false);

  const [
    incidentMessage,
    setIncidentMessage,
  ] = useState<string | null>(null);


  async function handleCreateIncident() {
    if (!result) {
      return;
    }

    setCreatingIncident(true);
    setError(null);
    setIncidentMessage(null);

    try {
      const relatedIndicatorIds =
        result.related_indicators.map(
          (item) => item.id,
        );

      const indicatorIds = Array.from(
        new Set([
          result.indicator.id,
          ...relatedIndicatorIds,
        ]),
      );

      const alertIds = Array.from(
        new Set(
          result.alerts.map(
            (alert) => alert.id,
          ),
        ),
      );

      const incident = await createIncident({
        title:
          `Threat investigation: ${result.indicator.value}`,
        description:
          "Incident created from the ThreatLens correlation workspace.",
        priority:
          result.indicator.severity === "CRITICAL"
            ? "CRITICAL"
            : result.indicator.severity === "HIGH"
              ? "HIGH"
              : "MEDIUM",
        indicator_ids: indicatorIds,
        alert_ids: alertIds,
      });

      setIncidentMessage(
        `Incident #${incident.id} created successfully.`,
      );
    } catch {
      setError(
        "Unable to create an incident from this correlation report.",
      );
    } finally {
      setCreatingIncident(false);
    }
  }


  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    const parsedId = Number(
      indicatorId,
    );

    if (
      !Number.isInteger(parsedId)
      || parsedId <= 0
    ) {
      setError(
        "Enter a valid indicator ID.",
      );

      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data =
        await getCorrelation(parsedId);

      setResult(data);
    } catch {
      setError(
        "Unable to run correlation for this indicator.",
      );
    } finally {
      setLoading(false);
    }
  }


  return (
    <div className="correlation-page">

      <section className="correlation-header">
        <div>
          <span className="correlation-kicker">
            ANALYSIS
          </span>

          <h1>
            Correlation Engine
          </h1>

          <p>
            Analyze persisted threat indicators
            and identify deterministic
            relationships across ThreatLens
            intelligence.
          </p>
        </div>

        <div className="correlation-engine-status">
          <ShieldCheck
            size={18}
            aria-hidden="true"
          />

          <span>
            Engine Ready
          </span>
        </div>
      </section>


      <section className="correlation-search-card">
        <div className="correlation-search-heading">
          <div className="correlation-icon-box">
            <GitBranch
              size={22}
              aria-hidden="true"
            />
          </div>

          <div>
            <h2>
              Threat Correlation
            </h2>

            <p>
              Enter an existing ThreatLens
              indicator ID to analyze its
              relationships.
            </p>
          </div>
        </div>

        <form
          className="correlation-form"
          onSubmit={handleSubmit}
        >
          <label htmlFor="correlation-id">
            Indicator ID
          </label>

          <div className="correlation-input-row">
            <div className="correlation-input-wrap">
              <Search
                size={18}
                aria-hidden="true"
              />

              <input
                id="correlation-id"
                type="number"
                min="1"
                step="1"
                placeholder="Enter indicator ID"
                value={indicatorId}
                onChange={(event) =>
                  setIndicatorId(
                    event.target.value,
                  )
                }
              />
            </div>

            <button
              type="submit"
              disabled={loading}
            >
              {loading
                ? "Running..."
                : "Run Correlation"}
            </button>
          </div>
        </form>

        {error && (
          <div
            className="correlation-error"
            role="alert"
          >
            <AlertTriangle
              size={18}
              aria-hidden="true"
            />

            <span>{error}</span>
          </div>
        )}
      </section>


      {!result && !loading && (
        <section className="correlation-empty">
          <GitBranch
            size={34}
            aria-hidden="true"
          />

          <h2>
            No correlation report yet
          </h2>

          <p>
            Select a persisted indicator by ID
            to calculate relationships,
            correlation scores, reasons, and
            related alerts.
          </p>
        </section>
      )}


      {result && (
        <>
          {incidentMessage && (
            <div
              className="correlation-incident-message"
              role="status"
            >
              {incidentMessage}
            </div>
          )}

          <section className="correlation-target-card">
            <div>
              <span className="correlation-section-label">
                TARGET INDICATOR
              </span>

              <h2>
                {result.indicator.value}
              </h2>

              <p>
                {result.indicator.indicator_type}
                {" • "}
                {result.indicator.source}
              </p>
            </div>

            <div className="correlation-target-actions">
              <span
                className={`correlation-severity severity-${result.indicator.severity.toLowerCase()}`}
              >
                {result.indicator.severity}
              </span>

              <button
                type="button"
                className="correlation-create-incident"
                onClick={() =>
                  void handleCreateIncident()
                }
                disabled={creatingIncident}
              >
                <Siren
                  size={17}
                  aria-hidden="true"
                />

                {creatingIncident
                  ? "Creating..."
                  : "Create Incident"}
              </button>
            </div>
          </section>


          <section className="correlation-metrics">
            <article>
              <Activity
                size={20}
                aria-hidden="true"
              />

              <span>
                Compared
              </span>

              <strong>
                {
                  result.summary
                    .total_indicators_compared
                }
              </strong>
            </article>

            <article>
              <GitBranch
                size={20}
                aria-hidden="true"
              />

              <span>
                Related
              </span>

              <strong>
                {
                  result.summary
                    .related_indicators
                }
              </strong>
            </article>

            <article>
              <ShieldCheck
                size={20}
                aria-hidden="true"
              />

              <span>
                Strong
              </span>

              <strong>
                {
                  result.summary
                    .strong_correlations
                }
              </strong>
            </article>

            <article>
              <AlertTriangle
                size={20}
                aria-hidden="true"
              />

              <span>
                Related Alerts
              </span>

              <strong>
                {
                  result.summary
                    .related_alerts
                }
              </strong>
            </article>

            <article>
              <Activity
                size={20}
                aria-hidden="true"
              />

              <span>
                Highest Score
              </span>

              <strong>
                {
                  result.summary
                    .highest_correlation_score
                }
              </strong>
            </article>
          </section>


          <section className="correlation-results-card">
            <div className="correlation-section-heading">
              <div>
                <span className="correlation-section-label">
                  RELATIONSHIPS
                </span>

                <h2>
                  Correlated Indicators
                </h2>
              </div>

              <span>
                {
                  result.related_indicators
                    .length
                }{" "}
                matches
              </span>
            </div>

            {result.related_indicators.length === 0 ? (
              <div className="correlation-no-results">
                No indicators met the
                correlation threshold.
              </div>
            ) : (
              <div className="correlation-list">
                {result.related_indicators.map(
                  (item) => (
                    <article
                      key={item.id}
                      className="correlation-result"
                    >
                      <div className="correlation-result-main">
                        <div className="correlation-result-title">
                          <span>
                            #{item.id}
                          </span>

                          <strong>
                            {item.value}
                          </strong>
                        </div>

                        <div className="correlation-result-meta">
                          <span>
                            {
                              item.indicator_type
                            }
                          </span>

                          <span>
                            {item.severity}
                          </span>

                          <span>
                            {item.source}
                          </span>
                        </div>

                        <div className="correlation-reasons">
                          {item.reasons.map(
                            (reason) => (
                              <span
                                key={reason}
                              >
                                {reason}
                              </span>
                            ),
                          )}
                        </div>
                      </div>

                      <div className="correlation-score-box">
                        <span>
                          {
                            correlationLevel(
                              item.correlation_score,
                            )
                          }
                        </span>

                        <strong>
                          {
                            item.correlation_score
                          }
                        </strong>

                        <small>
                          / 100
                        </small>

                        <ArrowRight
                          size={17}
                          aria-hidden="true"
                        />
                      </div>
                    </article>
                  ),
                )}
              </div>
            )}
          </section>


          <section className="correlation-results-card">
            <div className="correlation-section-heading">
              <div>
                <span className="correlation-section-label">
                  SECURITY EVENTS
                </span>

                <h2>
                  Related Alerts
                </h2>
              </div>

              <span>
                {result.alerts.length} alerts
              </span>
            </div>

            {result.alerts.length === 0 ? (
              <div className="correlation-no-results">
                No related alerts were found.
              </div>
            ) : (
              <div className="correlation-alert-list">
                {result.alerts.map(
                  (alert) => (
                    <article
                      key={alert.id}
                      className="correlation-alert"
                    >
                      <div>
                        <span>
                          Alert #{alert.id}
                        </span>

                        <strong>
                          {alert.title}
                        </strong>
                      </div>

                      <div className="correlation-alert-meta">
                        <span>
                          {alert.severity}
                        </span>

                        <span>
                          {alert.status}
                        </span>
                      </div>
                    </article>
                  ),
                )}
              </div>
            )}
          </section>
        </>
      )}

    </div>
  );
}


export default Correlation;