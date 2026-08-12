import apiClient from "./client";

export interface DashboardSummary {
  total_indicators: number;
  critical_indicators: number;
  high_indicators: number;
  active_alerts: number;
  average_threat_score: number;
}

export async function getDashboardSummary(): Promise<DashboardSummary> {
  const response = await apiClient.get<DashboardSummary>(
    "/dashboard/summary"
  );

  return response.data;
}