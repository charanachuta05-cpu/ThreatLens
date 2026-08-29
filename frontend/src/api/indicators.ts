import apiClient from "./client";

export type IndicatorType =
  | "IP"
  | "DOMAIN"
  | "URL"
  | "HASH";

export type IndicatorSeverity =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export interface Indicator {
  id: number;
  indicator_type: IndicatorType;
  value: string;
  severity: IndicatorSeverity;
  source: string;
  description: string | null;
  threat_score: number;
  reputation_score: number;
  confidence_score: number;
  tags: string[];
  created_at: string;
}

export interface IndicatorQuery {
  skip?: number;
  limit?: number;
  search?: string;
  severity?: string;
  source?: string;
  min_score?: number;
  sort_by?: string;
  order?: "asc" | "desc";
}

export interface IndicatorCreate {
  indicator_type: IndicatorType;
  value: string;
  severity: IndicatorSeverity;
  source: string;
  description?: string | null;
}

export async function getIndicators(
  params: IndicatorQuery = {},
): Promise<Indicator[]> {
  const response = await apiClient.get<Indicator[]>(
    "/indicators/",
    {
      params,
    },
  );

  return response.data;
}

export async function createIndicator(
  payload: IndicatorCreate,
): Promise<Indicator> {
  const response = await apiClient.post<Indicator>(
    "/indicators/",
    payload,
  );

  return response.data;
}