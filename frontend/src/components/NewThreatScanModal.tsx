import {
  AlertCircle,
  CheckCircle2,
  Loader2,
  RotateCcw,
  Search,
  X,
} from "lucide-react";
import axios from "axios";
import type { FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";

import {
  createIndicator,
  type Indicator,
  type IndicatorSeverity,
  type IndicatorType,
} from "../api/indicators";

import "./NewThreatScanModal.css";

interface NewThreatScanModalProps {
  open: boolean;
  onClose: () => void;
  onScanComplete: (
    indicator: Indicator,
  ) => void | Promise<void>;
}

interface ScanFormState {
  indicatorType: IndicatorType;
  value: string;
  severity: IndicatorSeverity;
  source: string;
  description: string;
}

const INITIAL_FORM: ScanFormState = {
  indicatorType: "IP",
  value: "",
  severity: "MEDIUM",
  source: "Manual Threat Scan",
  description: "",
};

function getPlaceholder(
  type: IndicatorType,
): string {
  switch (type) {
    case "IP":
      return "203.0.113.25";

    case "DOMAIN":
      return "suspicious-example.com";

    case "URL":
      return "https://example.com/path";

    case "HASH":
      return "Enter MD5, SHA-1, or SHA-256 hash";

    default:
      return "Enter indicator";
  }
}

function validateIndicator(
  type: IndicatorType,
  rawValue: string,
): string {
  const value = rawValue.trim();

  if (!value) {
    return "Enter an indicator to scan.";
  }

  if (value.length > 2048) {
    return "The indicator is too long.";
  }

  if (type === "IP") {
    const ipv4Pattern =
      /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

    if (!ipv4Pattern.test(value)) {
      return "Enter a valid IPv4 address.";
    }
  }

  if (type === "DOMAIN") {
    const domainPattern =
      /^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;

    if (!domainPattern.test(value)) {
      return "Enter a valid domain name.";
    }
  }

  if (type === "URL") {
    try {
      const parsedUrl = new URL(value);

      if (
        parsedUrl.protocol !== "http:" &&
        parsedUrl.protocol !== "https:"
      ) {
        return "Only HTTP and HTTPS URLs are supported.";
      }
    } catch {
      return "Enter a valid URL.";
    }
  }

  if (type === "HASH") {
    const hashPattern =
      /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;

    if (!hashPattern.test(value)) {
      return "Enter a valid MD5, SHA-1, or SHA-256 hash.";
    }
  }

  return "";
}

function getRequestError(
  error: unknown,
): string {
  if (!axios.isAxiosError(error)) {
    return "Threat scan failed. Please try again.";
  }

  const data = error.response?.data;

  const detail =
    data?.detail ??
    data?.error?.message;

  if (typeof detail === "string") {
    return detail;
  }

  if (Array.isArray(detail)) {
    const firstMessage =
      detail[0]?.msg;

    if (typeof firstMessage === "string") {
      return firstMessage;
    }
  }

  switch (error.response?.status) {
    case 400:
      return "ThreatLens could not process this indicator.";

    case 401:
      return "Your session has expired. Please sign in again.";

    case 403:
      return "You do not have permission to run threat scans.";

    case 404:
      return "The threat scanning endpoint could not be found.";

    case 409:
      return "This threat indicator already exists.";

    case 422:
      return "The threat scan request is invalid.";

    case 429:
      return "Too many requests. Please wait and try again.";

    case 500:
      return "ThreatLens encountered an internal error while analyzing the indicator.";

    default:
      return "Threat scan failed. Please try again.";
  }
}

function NewThreatScanModal({
  open,
  onClose,
  onScanComplete,
}: NewThreatScanModalProps) {
  const [form, setForm] =
    useState<ScanFormState>(INITIAL_FORM);

  const [submitting, setSubmitting] =
    useState(false);

  const [error, setError] =
    useState("");

  const [result, setResult] =
    useState<Indicator | null>(null);

  const placeholder = useMemo(
    () => getPlaceholder(form.indicatorType),
    [form.indicatorType],
  );

  useEffect(() => {
    if (!open) {
      return;
    }

    const handleKeyDown = (
      event: KeyboardEvent,
    ) => {
      if (
        event.key === "Escape" &&
        !submitting
      ) {
        setForm(INITIAL_FORM);
        setError("");
        setResult(null);
        onClose();
      }
    };

    window.addEventListener(
      "keydown",
      handleKeyDown,
    );

    return () => {
      window.removeEventListener(
        "keydown",
        handleKeyDown,
      );
    };
  }, [open, submitting, onClose]);

  if (!open) {
    return null;
  }

  const resetForm = () => {
    setForm(INITIAL_FORM);
    setError("");
    setResult(null);
  };

  const handleClose = () => {
    if (submitting) {
      return;
    }

    resetForm();
    onClose();
  };

  const handleSubmit = async (
    event: FormEvent<HTMLFormElement>,
  ) => {
    event.preventDefault();

    const validationError =
      validateIndicator(
        form.indicatorType,
        form.value,
      );

    if (validationError) {
      setError(validationError);
      return;
    }

    try {
      setSubmitting(true);
      setError("");
      setResult(null);

      const indicator =
        await createIndicator({
          indicator_type:
            form.indicatorType,

          value:
            form.value.trim(),

          severity:
            form.severity,

          source:
            form.source.trim() ||
            "Manual Threat Scan",

          description:
            form.description.trim() ||
            null,
        });

      setResult(indicator);

      await onScanComplete(indicator);
    } catch (requestError) {
      console.error(
        "Threat scan failed:",
        requestError,
      );

      setError(
        getRequestError(requestError),
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="threat-scan-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (
          event.target ===
          event.currentTarget
        ) {
          handleClose();
        }
      }}
    >
      <section
        className="threat-scan-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="threat-scan-title"
      >
        <header className="threat-scan-header">
          <div>
            <div className="threat-scan-eyebrow">
              <Search size={14} />
              THREAT INTELLIGENCE
            </div>

            <h2 id="threat-scan-title">
              New Threat Scan
            </h2>

            <p>
              Submit an indicator of
              compromise for ThreatLens
              analysis.
            </p>
          </div>

          <button
            type="button"
            className="threat-scan-close"
            onClick={handleClose}
            disabled={submitting}
            aria-label="Close threat scan"
          >
            <X size={20} />
          </button>
        </header>

        {result ? (
          <div className="threat-scan-result">
            <div className="threat-scan-result-icon">
              <CheckCircle2 size={44} />
            </div>

            <span className="threat-scan-result-label">
              ANALYSIS COMPLETE
            </span>

            <h3>
              Threat Scan Complete
            </h3>

            <div className="threat-scan-ioc">
              <span>
                {result.indicator_type}
              </span>

              <strong>
                {result.value}
              </strong>
            </div>

            <div className="threat-scan-result-grid">
              <div>
                <span>Severity</span>

                <strong
                  className={`threat-result-severity threat-result-${result.severity.toLowerCase()}`}
                >
                  {result.severity}
                </strong>
              </div>

              <div>
                <span>
                  Threat Score
                </span>

                <strong>
                  {result.threat_score}
                </strong>
              </div>

              <div>
                <span>
                  Reputation
                </span>

                <strong>
                  {result.reputation_score}
                </strong>
              </div>

              <div>
                <span>
                  Confidence
                </span>

                <strong>
                  {result.confidence_score}
                </strong>
              </div>
            </div>

            {result.tags.length > 0 && (
              <div className="threat-scan-tags">
                <span className="threat-scan-tags-title">
                  Analysis Tags
                </span>

                <div>
                  {result.tags.map(
                    (tag) => (
                      <span
                        key={tag}
                        className="threat-scan-tag"
                      >
                        {tag}
                      </span>
                    ),
                  )}
                </div>
              </div>
            )}

            <div className="threat-scan-result-actions">
              <button
                type="button"
                className="threat-scan-secondary"
                onClick={resetForm}
              >
                <RotateCcw size={16} />
                Scan Another
              </button>

              <button
                type="button"
                className="threat-scan-primary"
                onClick={handleClose}
              >
                Done
              </button>
            </div>
          </div>
        ) : (
          <form
            className="threat-scan-form"
            onSubmit={handleSubmit}
          >
            <div className="threat-scan-field">
              <label htmlFor="scan-type">
                Indicator Type
              </label>

              <select
                id="scan-type"
                value={form.indicatorType}
                disabled={submitting}
                onChange={(event) => {
                  setForm((current) => ({
                    ...current,
                    indicatorType:
                      event.target
                        .value as IndicatorType,
                    value: "",
                  }));

                  setError("");
                }}
              >
                <option value="IP">
                  IP Address
                </option>

                <option value="DOMAIN">
                  Domain
                </option>

                <option value="URL">
                  URL
                </option>

                <option value="HASH">
                  File Hash
                </option>
              </select>
            </div>

            <div className="threat-scan-field">
              <label htmlFor="scan-value">
                Indicator
              </label>

              <input
                id="scan-value"
                type="text"
                value={form.value}
                placeholder={placeholder}
                autoFocus
                autoComplete="off"
                spellCheck={false}
                disabled={submitting}
                onChange={(event) => {
                  setForm((current) => ({
                    ...current,
                    value:
                      event.target.value,
                  }));

                  setError("");
                }}
              />

              <small>
                Enter the IOC exactly as
                observed by the analyst.
              </small>
            </div>

            <div className="threat-scan-row">
              <div className="threat-scan-field">
                <label htmlFor="scan-severity">
                  Initial Severity
                </label>

                <select
                  id="scan-severity"
                  value={form.severity}
                  disabled={submitting}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      severity:
                        event.target
                          .value as IndicatorSeverity,
                    }))
                  }
                >
                  <option value="LOW">
                    Low
                  </option>

                  <option value="MEDIUM">
                    Medium
                  </option>

                  <option value="HIGH">
                    High
                  </option>

                  <option value="CRITICAL">
                    Critical
                  </option>
                </select>
              </div>

              <div className="threat-scan-field">
                <label htmlFor="scan-source">
                  Source
                </label>

                <input
                  id="scan-source"
                  type="text"
                  value={form.source}
                  disabled={submitting}
                  maxLength={255}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      source:
                        event.target.value,
                    }))
                  }
                />
              </div>
            </div>

            <div className="threat-scan-field">
              <label htmlFor="scan-description">
                Analyst Notes
                <span>Optional</span>
              </label>

              <textarea
                id="scan-description"
                rows={4}
                value={form.description}
                placeholder="Add context about where this indicator was observed..."
                disabled={submitting}
                maxLength={2000}
                onChange={(event) =>
                  setForm((current) => ({
                    ...current,
                    description:
                      event.target.value,
                  }))
                }
              />
            </div>

            {error && (
              <div
                className="threat-scan-error"
                role="alert"
              >
                <AlertCircle size={18} />

                <span>
                  {error}
                </span>
              </div>
            )}

            <div className="threat-scan-info">
              ThreatLens will submit this
              IOC to the existing threat
              intelligence pipeline for
              enrichment, scoring, alerting,
              and investigation.
            </div>

            <footer className="threat-scan-actions">
              <button
                type="button"
                className="threat-scan-secondary"
                onClick={handleClose}
                disabled={submitting}
              >
                Cancel
              </button>

              <button
                type="submit"
                className="threat-scan-primary"
                disabled={
                  submitting ||
                  !form.value.trim()
                }
              >
                {submitting ? (
                  <>
                    <Loader2
                      size={17}
                      className="threat-scan-spinner"
                    />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Search size={17} />
                    Scan Threat
                  </>
                )}
              </button>
            </footer>
          </form>
        )}
      </section>
    </div>
  );
}

export default NewThreatScanModal;