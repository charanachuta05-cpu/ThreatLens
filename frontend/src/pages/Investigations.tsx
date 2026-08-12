import { useEffect, useState } from "react";

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
        console.error(
          "Failed to load investigation indicators:",
          err,
        );

        setError("Unable to load indicators.");
      } finally {
        setLoadingIndicators(false);
      }
    }

    void loadIndicators();
  }, []);

  async function openInvestigation(indicatorId: number) {
    try {
      setSelectedId(indicatorId);
      setLoadingInvestigation(true);
      setError("");
      setInvestigation(null);

      const data = await getInvestigation(indicatorId);

      const selectedIndicator = indicators.find(
        (indicator) => indicator.id === indicatorId,
      );

      const backendIndicator = data?.indicator;
      const scores = data?.scores;

      const normalizedInvestigation: InvestigationView = {
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
          Number(scores?.threat_score ?? 0),

        reputation_score:
          Number(
            scores?.reputation_score ?? 0,
          ),

        confidence_score:
          Number(
            scores?.confidence_score ?? 0,
          ),

        tags: Array.isArray(data?.tags)
          ? data.tags
          : [],

        related_indicators:
          Array.isArray(
            data?.related_indicators,
          )
            ? data.related_indicators
            : [],

        alerts: Array.isArray(data?.alerts)
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
      console.error(
        "Failed to load investigation:",
        err,
      );

      setError(
        "Unable to load investigation data.",
      );

      setInvestigation(null);
    } finally {
      setLoadingInvestigation(false);
    }
  }

  function safeSeverity(
    severity: string | null | undefined,
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

    if (typeof recommendation === "string") {
      return recommendation;
    }

    return (
      recommendation.summary ||
      "No recommendation available."
    );
  }

  const filteredIndicators =
    indicators.filter((indicator) =>
      String(indicator.value ?? "")
        .toLowerCase()
        .includes(search.toLowerCase()),
    );

  return (
    <div className="investigations-page">
      <div className="investigation-page-header">
        <div>
          <h1>Threat Investigation</h1>

          <p>
            Investigate indicators and review
            correlated threat intelligence.
          </p>
        </div>
      </div>

      <div className="investigation-layout">
        {/* SIDEBAR */}

        <div className="investigation-sidebar">
          <div className="investigation-sidebar-header">
            <div>
              <h3>Indicators</h3>

              <span>
                Select an IOC to investigate
              </span>
            </div>

            <Target size={18} />
          </div>

          <div className="investigation-search">
            <Search size={15} />

            <input
              type="search"
              placeholder="Search IOC..."
              value={search}
              onChange={(event) =>
                setSearch(event.target.value)
              }
            />
          </div>

          {loadingIndicators && (
            <div className="investigation-state">
              Loading indicators...
            </div>
          )}

          {!loadingIndicators &&
            filteredIndicators.length === 0 && (
              <div className="investigation-state">
                No indicators found.
              </div>
            )}

          <div className="investigation-indicator-list">
            {filteredIndicators.map(
              (indicator) => (
                <button
                  type="button"
                  key={indicator.id}
                  className={`investigation-indicator ${
                    selectedId === indicator.id
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

                    <strong title={indicator.value}>
                      {indicator.value}
                    </strong>
                  </div>

                  <span
                    className={`severity-badge ${safeSeverity(
                      indicator.severity,
                    )}`}
                  >
                    {indicator.severity}
                  </span>
                </button>
              ),
            )}
          </div>
        </div>

        {/* DETAILS */}

        <div className="investigation-content">
          {loadingInvestigation && (
            <div className="investigation-empty">
              <ShieldAlert size={40} />

              <h3>
                Loading investigation...
              </h3>

              <p>
                Retrieving threat intelligence.
              </p>
            </div>
          )}

          {!loadingInvestigation &&
            !investigation &&
            !error && (
              <div className="investigation-empty">
                <ShieldAlert size={40} />

                <h3>Select an indicator</h3>

                <p>
                  Choose an IOC from the list to
                  begin an investigation.
                </p>
              </div>
            )}

          {error && (
            <div className="investigation-error">
              <AlertTriangle size={20} />

              <span>{error}</span>
            </div>
          )}

          {!loadingInvestigation &&
            investigation && (
              <>
                {/* HEADER */}

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
                    className={`severity-badge large ${safeSeverity(
                      investigation.severity,
                    )}`}
                  >
                    {investigation.severity ||
                      "UNKNOWN"}
                  </span>
                </div>

                {/* SCORES */}

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
                      {investigation.reputation_score}
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
                      {investigation.confidence_score}
                    </strong>

                    <small>
                      Intelligence confidence
                    </small>
                  </div>
                </div>

                {/* DETAILS */}

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
                        {investigation.indicator_type}
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
                      <span>Description</span>

                      <strong>
                        {investigation.description ||
                          "No description available."}
                      </strong>
                    </div>
                  </div>
                </div>

                {/* TAGS */}

                <div className="investigation-card">
                  <div className="investigation-card-header">
                    <h3>Threat Tags</h3>
                  </div>

                  {investigation.tags.length >
                  0 ? (
                    <div className="investigation-tags">
                      {investigation.tags.map(
                        (tag) => (
                          <span
                            className="investigation-tag"
                            key={tag}
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

                {/* RECOMMENDATION */}

                <div className="recommendation-card">
                  <div className="recommendation-icon">
                    <ShieldAlert size={20} />
                  </div>

                  <div>
                    <span>
                      Analyst Recommendation
                    </span>

                    <p>
                      {renderRecommendation(
                        investigation.recommendation,
                      )}
                    </p>

                    {typeof investigation.recommendation !==
                      "string" &&
                      investigation.recommendation && (
                        <div>
                          <strong>
                            Priority:{" "}
                            {
                              investigation
                                .recommendation
                                .priority
                            }
                          </strong>

                          {investigation.recommendation
                            .actions
                            .length > 0 && (
                            <ul>
                              {investigation.recommendation.actions.map(
                                (action) => (
                                  <li key={action}>
                                    {action}
                                  </li>
                                ),
                              )}
                            </ul>
                          )}
                        </div>
                      )}
                  </div>
                </div>

                {/* RELATED INDICATORS */}

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
                    <div className="related-list">
                      {investigation.related_indicators.map(
                        (related) => (
                          <div
                            className="related-row"
                            key={related.id}
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
                              <span
                                className={`severity-badge ${safeSeverity(
                                  related.severity,
                                )}`}
                              >
                                {related.severity ||
                                  "UNKNOWN"}
                              </span>

                              <b>
                                {
                                  related.correlation_score
                                }
                              </b>
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  ) : (
                    <div className="no-investigation-data">
                      No related indicators
                      found.
                    </div>
                  )}
                </div>

                {/* RELATED ALERTS */}

                <div className="investigation-card">
                  <div className="investigation-card-header">
                    <h3>
                      Related Alerts
                    </h3>

                    <span>
                      {
                        investigation.alerts
                          .length
                      }
                    </span>
                  </div>

                  {investigation.alerts.length >
                  0 ? (
                    <div className="related-list">
                      {investigation.alerts.map(
                        (alert) => (
                          <div
                            className="related-row"
                            key={alert.id}
                          >
                            <div>
                              <strong>
                                {alert.title}
                              </strong>

                              <span>
                                Alert ID:{" "}
                                {alert.id}
                              </span>
                            </div>
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
