import { useEffect, useState } from "react";
import axios from "axios";

import {
  AlertTriangle,
  Search,
  ShieldAlert,
  Target,
} from "lucide-react";

import {
  getIndicators,
  type Indicator,
} from "../api/indicators";

import {
  getInvestigation,
  type Investigation,
} from "../api/investigations";

import "./Investigations.css";

interface InvestigationView {
  indicator_id: number;
  indicator_type: string;
  value: string;
  severity: string;
  source: string | null;
  description: string | null;
  threat_score: number;
  reputation_score: number;
  confidence_score: number;
  explanation: Investigation["explanation"];
  tags: string[];
  related_indicators: Investigation["related_indicators"];
  alerts: Investigation["alerts"];
  recommendation: Investigation["recommendation"];
}

function Investigations() {
  const [indicators, setIndicators] = useState<Indicator[]>(
    [],
  );

  const [investigation, setInvestigation] =
    useState<InvestigationView | null>(null);

  const [selectedId, setSelectedId] =
    useState<number | null>(null);

  const [search, setSearch] = useState("");

  const [loadingIndicators, setLoadingIndicators] =
    useState(true);

  const [loadingInvestigation, setLoadingInvestigation] =
    useState(false);

  const [error, setError] = useState("");

  useEffect(() => {
    async function loadIndicators() {
      try {
        setLoadingIndicators(true);
        setError("");

        const data = await getIndicators({
          skip: 0,
          limit: 50,
        });

        setIndicators(data);
      } catch (err) {
        if (axios.isAxiosError(err)) {
          const status = err.response?.status;

          if (status === 401) {
            setError(
              "Your session has expired. Please log in again.",
            );
          } else if (status === 403) {
            setError(
              "You do not have permission to view indicators.",
            );
          } else {
            console.error(
              "Failed to load investigation indicators:",
              err,
            );

            setError(
              "Unable to load indicators.",
            );
          }
        } else {
          console.error(
            "Failed to load investigation indicators:",
            err,
          );

          setError(
            "Unable to load indicators.",
          );
        }
      } finally {
        setLoadingIndicators(false);
      }
    }

    void loadIndicators();
  }, []);

  async function openInvestigation(
    indicatorId: number,
  ) {
    try {
      setSelectedId(indicatorId);
      setLoadingInvestigation(true);
      setError("");
      setInvestigation(null);

      const data = await getInvestigation(
        indicatorId,
      );

      const selectedIndicator =
        indicators.find(
          (indicator) =>
            indicator.id === indicatorId,
        );

      const backendIndicator =
        data?.indicator;

      const scores = data?.scores;

      const normalizedInvestigation:
        InvestigationView = {
        indicator_id:
          backendIndicator?.id ??
          indicatorId,

        indicator_type:
          backendIndicator?.type ??
          selectedIndicator?.indicator_type ??
          "UNKNOWN",

        value:
          backendIndicator?.value ??
          selectedIndicator?.value ??
          "Unknown indicator",

        severity:
          backendIndicator?.severity ??
          selectedIndicator?.severity ??
          "UNKNOWN",

        source:
          backendIndicator?.source ??
          selectedIndicator?.source ??
          null,

        description:
          selectedIndicator?.description ??
          null,

        threat_score:
          Number(
            scores?.threat_score ?? 0,
          ),

        reputation_score:
          Number(
            scores?.reputation_score ?? 0,
          ),

        confidence_score:
          Number(
            scores?.confidence_score ?? 0,
          ),

        explanation: data.explanation,

        tags:
          Array.isArray(data?.tags)
            ? data.tags
            : [],

        related_indicators:
          Array.isArray(
            data?.related_indicators,
          )
            ? data.related_indicators
            : [],

        alerts:
          Array.isArray(data?.alerts)
            ? data.alerts
            : [],

        recommendation:
          data?.recommendation ??
          "No recommendation available.",
      };

      setInvestigation(
        normalizedInvestigation,
      );
    } catch (err) {
      /*
       * Handle expected API authorization
       * responses without treating them as
       * unexpected application failures.
       */
      if (axios.isAxiosError(err)) {
        const status =
          err.response?.status;

        switch (status) {
          case 401:
            setError(
              "Your session has expired. Please log in again.",
            );
            break;

          case 403:
            setError(
              "You do not have permission to investigate indicators.",
            );
            break;

          case 404:
            setError(
              "Indicator not found.",
            );
            break;

          default:
            console.error(
              "Failed to load investigation:",
              err,
            );

            setError(
              "Unable to load investigation data.",
            );
        }
      } else {
        console.error(
          "Failed to load investigation:",
          err,
        );

        setError(
          "Unable to load investigation data.",
        );
      }

      setInvestigation(null);
    } finally {
      setLoadingInvestigation(false);
    }
  }

  function safeSeverity(
    severity:
      | string
      | null
      | undefined,
  ): string {
    return (
      severity
        ?.toString()
        .trim()
        .toLowerCase() ||
      "unknown"
    );
  }

  function renderRecommendation(
    recommendation:
      | InvestigationView["recommendation"],
  ) {
    if (!recommendation) {
      return "No recommendation available.";
    }

    if (
      typeof recommendation ===
      "string"
    ) {
      return recommendation;
    }

    return (
      recommendation.summary ||
      "No recommendation available."
    );
  }

  const filteredIndicators =
    indicators.filter(
      (indicator) =>
        String(
          indicator.value ?? "",
        )
          .toLowerCase()
          .includes(
            search.toLowerCase(),
          ),
    );

  return (
    <div className="investigations-page">
      <div className="investigation-page-header">
        <div>
          <h1>
            Threat Investigation
          </h1>

          <p>
            Investigate indicators and review
            correlated threat intelligence.
          </p>
        </div>
      </div>

      <div className="investigation-layout">
        <div className="investigation-sidebar">
          <div className="investigation-sidebar-header">
            <div>
              <h3>Indicators</h3>

              <span>
                {indicators.length} indicators
              </span>
            </div>

            <Target
              size={20}
              aria-hidden="true"
            />
          </div>

          <div className="investigation-search">
            <Search
              size={17}
              aria-hidden="true"
            />

            <input
              type="search"
              placeholder="Search IOC..."
              value={search}
              onChange={(event) =>
                setSearch(
                  event.target.value,
                )
              }
              aria-label="Search indicators"
            />
          </div>

          {loadingIndicators && (
            <div className="investigation-state">
              Loading indicators...
            </div>
          )}

          {!loadingIndicators &&
            error &&
            indicators.length === 0 && (
              <div className="investigation-error">
                <AlertTriangle
                  size={18}
                  aria-hidden="true"
                />

                <span>{error}</span>
              </div>
            )}

          {!loadingIndicators &&
            !error &&
            filteredIndicators.length ===
              0 && (
              <div className="investigation-state">
                No indicators found.
              </div>
            )}

          <div className="investigation-indicator-list">
            {filteredIndicators.map(
              (indicator) => {
                const severity =
                  safeSeverity(
                    indicator.severity,
                  );

                return (
                  <button
                    type="button"
                    key={indicator.id}
                    className={`investigation-indicator ${
                      selectedId ===
                      indicator.id
                        ? "selected"
                        : ""
                    }`}
                    onClick={() =>
                      void openInvestigation(
                        indicator.id,
                      )
                    }
                  >
                    <div>
                      <span className="investigation-type">
                        {indicator.indicator_type}
                      </span>

                      <strong>
                        {indicator.value}
                      </strong>
                    </div>

                    <span
                      className={`severity-badge severity-${severity}`}
                    >
                      {indicator.severity}
                    </span>
                  </button>
                );
              },
            )}
          </div>
        </div>

        <div className="investigation-content">
          {loadingInvestigation && (
            <div className="investigation-empty">
              <ShieldAlert
                size={42}
                aria-hidden="true"
              />

              <h3>
                Loading investigation...
              </h3>

              <p>
                Gathering threat intelligence.
              </p>
            </div>
          )}

          {!loadingInvestigation &&
            !investigation &&
            error && (
              <div className="investigation-error">
                <AlertTriangle
                  size={22}
                  aria-hidden="true"
                />

                <span>{error}</span>
              </div>
            )}

          {!loadingInvestigation &&
            !investigation &&
            !error && (
              <div className="investigation-empty">
                <ShieldAlert
                  size={42}
                  aria-hidden="true"
                />

                <h3>
                  Select an IOC to investigate
                </h3>

                <p>
                  Choose an indicator from the
                  list to view its threat
                  intelligence and correlations.
                </p>
              </div>
            )}

          {!loadingInvestigation &&
            investigation && (
              <>
                <div className="investigation-header">
                  <div>
                    <div className="investigation-header-type">
                      {investigation.indicator_type}
                    </div>

                    <h2>
                      {investigation.value}
                    </h2>

                    <p>
                      Source:{" "}
                      {investigation.source ||
                        "Unknown"}
                    </p>
                  </div>

                  <span
                    className={`severity-badge severity-${safeSeverity(
                      investigation.severity,
                    )}`}
                  >
                    {investigation.severity}
                  </span>
                </div>

                <div className="investigation-score-grid">
                  <div className="investigation-score-card">
                    <span>
                      Threat Score
                    </span>

                    <strong>
                      {investigation.threat_score}
                    </strong>

                    <small>
                      Overall threat assessment
                    </small>
                  </div>

                  <div className="investigation-score-card">
                    <span>
                      Reputation Score
                    </span>

                    <strong>
                      {
                        investigation.reputation_score
                      }
                    </strong>

                    <small>
                      External reputation
                    </small>
                  </div>

                  <div className="investigation-score-card">
                    <span>
                      Confidence Score
                    </span>

                    <strong>
                      {
                        investigation.confidence_score
                      }
                    </strong>

                    <small>
                      Intelligence confidence
                    </small>
                  </div>
                </div>

                <div className="investigation-card">
                  <div className="investigation-card-header">
                    <h3>
                      Enrichment Explanation
                    </h3>

                    <span>
                      Deterministic analysis
                    </span>
                  </div>

                  <div className="investigation-explanation">
                    <div className="investigation-explanation-section">
                      <div className="investigation-explanation-title">
                        <strong>Threat Score</strong>

                        <span>
                          {investigation.explanation.threat_score.value}/100
                        </span>
                      </div>

                      <ul className="investigation-explanation-reasons">
                        {investigation.explanation.threat_score.reasons.map(
                          (reason) => (
                            <li key={reason}>
                              {reason}
                            </li>
                          ),
                        )}
                      </ul>
                    </div>

                    <div className="investigation-explanation-section">
                      <div className="investigation-explanation-title">
                        <strong>Reputation Score</strong>

                        <span>
                          {investigation.explanation.reputation_score.value}/100
                        </span>
                      </div>

                      <ul className="investigation-explanation-reasons">
                        {investigation.explanation.reputation_score.reasons.map(
                          (reason) => (
                            <li key={reason}>
                              {reason}
                            </li>
                          ),
                        )}
                      </ul>
                    </div>

                    <div className="investigation-explanation-section">
                      <div className="investigation-explanation-title">
                        <strong>Confidence Score</strong>

                        <span>
                          {investigation.explanation.confidence_score.value}/100
                        </span>
                      </div>

                      <ul className="investigation-explanation-reasons">
                        {investigation.explanation.confidence_score.reasons.map(
                          (reason) => (
                            <li key={reason}>
                              {reason}
                            </li>
                          ),
                        )}
                      </ul>
                    </div>

                    {Object.keys(
                      investigation.explanation.tag_reasons,
                    ).length > 0 && (
                      <div className="investigation-explanation-section">
                        <div className="investigation-explanation-title">
                          <strong>Tag Reasoning</strong>

                          <span>
                            {
                              Object.keys(
                                investigation.explanation.tag_reasons,
                              ).length
                            } reasons
                          </span>
                        </div>

                        <div className="investigation-tag-reasons">
                          {Object.entries(
                            investigation.explanation.tag_reasons,
                          ).map(
                            ([tag, reason]) => (
                              <div
                                key={tag}
                                className="investigation-tag-reason"
                              >
                                <span>{tag}</span>

                                <p>{reason}</p>
                              </div>
                            ),
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                <div className="investigation-card">
                  <div className="investigation-card-header">
                    <h3>
                      Indicator Details
                    </h3>
                  </div>

                  <div className="investigation-details">
                    <div>
                      <span>
                        Indicator Type
                      </span>

                      <strong>
                        {
                          investigation.indicator_type
                        }
                      </strong>
                    </div>

                    <div>
                      <span>Source</span>

                      <strong>
                        {investigation.source ||
                          "Unknown"}
                      </strong>
                    </div>

                    <div>
                      <span>
                        Description
                      </span>

                      <strong>
                        {investigation.description ||
                          "No description available."}
                      </strong>
                    </div>
                  </div>
                </div>

                <div className="investigation-card">
                  <div className="investigation-card-header">
                    <h3>
                      Threat Tags
                    </h3>
                  </div>

                  {investigation.tags.length >
                  0 ? (
                    <div className="investigation-tags">
                      {investigation.tags.map(
                        (tag) => (
                          <span
                            key={tag}
                            className="investigation-tag"
                          >
                            {tag}
                          </span>
                        ),
                      )}
                    </div>
                  ) : (
                    <div className="no-investigation-data">
                      No threat tags assigned.
                    </div>
                  )}
                </div>

                <div className="investigation-card">
                  <div className="investigation-card-header">
                    <h3>
                      Analyst Recommendation
                    </h3>
                  </div>

                  <div className="investigation-recommendation">
                    <p>
                      {renderRecommendation(
                        investigation.recommendation,
                      )}
                    </p>

                    {typeof investigation.recommendation !==
                      "string" &&
                      investigation.recommendation && (
                        <>
                          <strong>
                            Priority:{" "}
                            {
                              investigation
                                .recommendation
                                .priority
                            }
                          </strong>

                          <ul>
                            {investigation.recommendation.actions.map(
                              (action) => (
                                <li key={action}>
                                  {action}
                                </li>
                              ),
                            )}
                          </ul>
                        </>
                      )}
                  </div>
                </div>

                <div className="investigation-card">
                  <div className="investigation-card-header">
                    <h3>
                      Related Indicators
                    </h3>

                    <span>
                      {
                        investigation
                          .related_indicators
                          .length
                      }
                    </span>
                  </div>

                  {investigation.related_indicators
                    .length > 0 ? (
                    <div className="related-indicators">
                      {investigation.related_indicators.map(
                        (related) => (
                          <div
                            key={related.id}
                            className="related-indicator"
                          >
                            <div>
                              <span>
                                {
                                  related.indicator_type
                                }
                              </span>

                              <strong>
                                {related.value}
                              </strong>
                            </div>

                            <div>
                              <span>
                                {related.severity}
                              </span>

                              <strong>
                                {
                                  related.correlation_score
                                }
                              </strong>
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  ) : (
                    <div className="no-investigation-data">
                      No related indicators found.
                    </div>
                  )}
                </div>

                <div className="investigation-card">
                  <div className="investigation-card-header">
                    <h3>
                      Related Alerts
                    </h3>

                    <span>
                      {investigation.alerts.length}
                    </span>
                  </div>

                  {investigation.alerts.length >
                  0 ? (
                    <div className="related-alerts">
                      {investigation.alerts.map(
                        (alert) => (
                          <div
                            key={alert.id}
                            className="related-alert"
                          >
                            <strong>
                              {alert.title}
                            </strong>

                            <span>
                              Alert ID:{" "}
                              {alert.id}
                            </span>
                          </div>
                        ),
                      )}
                    </div>
                  ) : (
                    <div className="no-investigation-data">
                      No related alerts found.
                    </div>
                  )}
                </div>
              </>
            )}
        </div>
      </div>
    </div>
  );
}

export default Investigations;