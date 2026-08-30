import apiClient from "./client";

export type IncidentPriority =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export type IncidentStatus =
  | "OPEN"
  | "IN_PROGRESS"
  | "RESOLVED"
  | "CLOSED";

export type IncidentResolutionType =
  | "TRUE_POSITIVE"
  | "FALSE_POSITIVE"
  | "BENIGN"
  | "DUPLICATE";

export interface IncidentAlert {
  id: number;
  title: string;
  severity: string;
  status: string;
  indicator_id: number | null;
}

export interface IncidentIndicator {
  id: number;
  indicator_type: string;
  value: string;
  severity: string;
  source: string | null;
  threat_score: number;
  reputation_score: number;
  confidence_score: number;
  tags: string[];
}

export interface IncidentNote {
  id: number;
  incident_id: number;
  author_id: number;
  content: string;
  created_at: string;
  updated_at: string | null;
}

export interface Incident {
  id: number;
  title: string;
  description: string;
  priority: IncidentPriority;
  status: IncidentStatus;
  created_by: number;
  assigned_to: number | null;
  created_at: string;
  updated_at: string | null;
  resolved_at: string | null;
  resolution_type: IncidentResolutionType | null;
  resolution_summary: string | null;
  resolved_by: number | null;
  alerts: IncidentAlert[];
  indicators: IncidentIndicator[];
  notes: IncidentNote[];
}

export interface IncidentTimelineEvent {
  id: string;
  event_type: "AUDIT" | "NOTE";
  action: string;
  actor: string;
  description: string;
  created_at: string;
}

export interface IncidentCreate {
  title: string;
  description: string;
  priority?: IncidentPriority;
  assigned_to?: number | null;
  alert_ids?: number[];
  indicator_ids?: number[];
}

export interface IncidentUpdate {
  title?: string;
  description?: string;
  priority?: IncidentPriority;
  status?: IncidentStatus;
  assigned_to?: number | null;
}

export interface IncidentResolve {
  resolution_type: IncidentResolutionType;
  resolution_summary: string;
}

export interface IncidentQuery {
  skip?: number;
  limit?: number;
  status?: IncidentStatus;
  priority?: IncidentPriority;
  assigned_to?: number;
  search?: string;
}

export async function getIncidents(
  params: IncidentQuery = {},
): Promise<Incident[]> {
  const response = await apiClient.get<Incident[]>(
    "/incidents/",
    {
      params,
    },
  );

  return response.data;
}

export async function getIncidentTimeline(
  incidentId: number,
): Promise<IncidentTimelineEvent[]> {
  const response = await apiClient.get<
    IncidentTimelineEvent[]
  >(
    `/incidents/${incidentId}/timeline`,
  );

  return response.data;
}

export async function createIncident(
  payload: IncidentCreate,
): Promise<Incident> {
  const response = await apiClient.post<Incident>(
    "/incidents/",
    payload,
  );

  return response.data;
}

export async function updateIncident(
  incidentId: number,
  payload: IncidentUpdate,
): Promise<Incident> {
  const response = await apiClient.put<Incident>(
    `/incidents/${incidentId}`,
    payload,
  );

  return response.data;
}

export async function resolveIncident(
  incidentId: number,
  payload: IncidentResolve,
): Promise<Incident> {
  const response = await apiClient.post<Incident>(
    `/incidents/${incidentId}/resolve`,
    payload,
  );

  return response.data;
}

export async function addIncidentNote(
  incidentId: number,
  content: string,
): Promise<IncidentNote> {
  const response = await apiClient.post<IncidentNote>(
    `/incidents/${incidentId}/notes`,
    {
      content,
    },
  );

  return response.data;
}

export async function linkIncidentAlert(
  incidentId: number,
  alertId: number,
): Promise<Incident> {
  const response = await apiClient.post<Incident>(
    `/incidents/${incidentId}/alerts/${alertId}`,
  );

  return response.data;
}

export async function unlinkIncidentAlert(
  incidentId: number,
  alertId: number,
): Promise<Incident> {
  const response = await apiClient.delete<Incident>(
    `/incidents/${incidentId}/alerts/${alertId}`,
  );

  return response.data;
}

export async function linkIncidentIndicator(
  incidentId: number,
  indicatorId: number,
): Promise<Incident> {
  const response = await apiClient.post<Incident>(
    `/incidents/${incidentId}/indicators/${indicatorId}`,
  );

  return response.data;
}

export async function unlinkIncidentIndicator(
  incidentId: number,
  indicatorId: number,
): Promise<Incident> {
  const response = await apiClient.delete<Incident>(
    `/incidents/${incidentId}/indicators/${indicatorId}`,
  );

  return response.data;
}
