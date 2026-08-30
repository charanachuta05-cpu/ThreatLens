import apiClient from "./client";

export interface CorrelationIndicator {
  id: number;
  value: string;
  indicator_type: string;
  severity: string;
  source: string;
  threat_score: number;
  reputation_score: number;
  confidence_score: number;
  tags: string[];
}

export interface CorrelatedIndicator {
  id: number;
  value: string;
  indicator_type: string;
  severity: string;
  source: string;
  threat_score: number;
  reputation_score: number;
  confidence_score: number;
  correlation_score: number;
  reasons: string[];
}

export interface CorrelationAlert {
  id: number;
  title: string;
  severity: string;
  status: string;
  indicator_id: number | null;
}

export interface CorrelationSummary {
  total_indicators_compared: number;
  related_indicators: number;
  strong_correlations: number;
  related_alerts: number;
  highest_correlation_score: number;
}

export interface CorrelationResponse {
  indicator: CorrelationIndicator;
  summary: CorrelationSummary;
  related_indicators: CorrelatedIndicator[];
  alerts: CorrelationAlert[];
}

export async function getCorrelation(
  indicatorId: number,
): Promise<CorrelationResponse> {
  const response =
    await apiClient.get<CorrelationResponse>(
      `/correlation/${indicatorId}`,
    );

  return response.data;
}