import apiClient from "./client";

export interface InvestigationIndicator {
  id: number;
  value: string;
  type: string;
  severity: string;
  source: string | null;
}

export interface InvestigationScores {
  threat_score: number;
  reputation_score: number;
  confidence_score: number;
}

export interface ScoreExplanation {
  value: number;
  reasons: string[];
}

export interface EnrichmentExplanation {
  threat_score: ScoreExplanation;
  reputation_score: ScoreExplanation;
  confidence_score: ScoreExplanation;
  tag_reasons: Record<string, string>;
}

export interface InvestigationAlert {
  id: number;
  title: string;
}

export interface RelatedIndicator {
  id: number;
  indicator_type: string;
  value: string;
  severity: string;
  source: string | null;
  correlation_score: number;
  reasons: string[];
}

export interface InvestigationRecommendation {
  summary: string;
  priority: string;
  actions: string[];
}

export interface Investigation {
  indicator: InvestigationIndicator;
  scores: InvestigationScores;
  explanation: EnrichmentExplanation;
  tags: string[];
  related_indicators: RelatedIndicator[];
  alerts: InvestigationAlert[];
  recommendation:
    | InvestigationRecommendation
    | string
    | null;
}

export async function getInvestigation(
  indicatorId: number,
): Promise<Investigation> {
  if (!Number.isInteger(indicatorId)) {
    throw new Error("Invalid indicator ID.");
  }

  const response = await apiClient.get<Investigation>(
    `/investigations/${indicatorId}`,
  );

  return response.data;
}