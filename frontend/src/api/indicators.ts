import apiClient from "./client";

export interface Indicator {
  id: number;
  indicator_type: "IP" | "DOMAIN" | "URL" | "HASH";
  value: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
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