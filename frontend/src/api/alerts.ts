import apiClient from "./client";

export interface Alert {
  id: number;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  source: string | null;
  created_by: number | null;
  assigned_to: number | null;
  indicator_id: number | null;
  created_at: string;
  updated_at: string | null;
}

export interface AlertQuery {
  skip?: number;
  limit?: number;
  search?: string;
  severity?: string;
  status?: string;
  source?: string;
}

export interface AlertUpdate {
  title?: string;
  description?: string;
  severity?: string;
  status?: string;
  source?: string;
  assigned_to?: number | null;
}

export async function getAlerts(
  params: AlertQuery = {},
): Promise<Alert[]> {
  const response =
    await apiClient.get<Alert[]>(
      "/alerts/",
      {
        params,
      },
    );

  return response.data;
}

export async function updateAlert(
  alertId: number,
  alertData: AlertUpdate,
): Promise<Alert> {
  const response =
    await apiClient.put<Alert>(
      `/alerts/${alertId}`,
      alertData,
    );

  return response.data;
}
