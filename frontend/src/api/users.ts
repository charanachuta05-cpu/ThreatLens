import apiClient from "./client";

export type UserRole =
  | "admin"
  | "analyst"
  | "viewer";

export interface CurrentUser {
  id: number;
  username: string;
  email: string;
  role: UserRole;
}

export interface AssignableUser {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface HealthStatus {
  status: string;
  database: string;
}

export interface AdminDashboardResponse {
  message: string;
  user: string;
}

export async function getCurrentUser(): Promise<CurrentUser> {
  const response =
    await apiClient.get<CurrentUser>(
      "/users/me",
    );

  return response.data;
}

export async function getAssignableUsers(): Promise<
  AssignableUser[]
> {
  const response =
    await apiClient.get<AssignableUser[]>(
      "/users/assignable",
    );

  return response.data;
}

export async function getHealthStatus(): Promise<HealthStatus> {
  const response =
    await apiClient.get<HealthStatus>(
      "/health",
    );

  return response.data;
}

export async function getAdminDashboard(): Promise<
  AdminDashboardResponse
> {
  const response =
    await apiClient.get<AdminDashboardResponse>(
      "/admin/dashboard",
    );

  return response.data;
}

export interface AccessRequest {
  id: number;
  user_id: number;
  username: string;
  email: string;
  requested_role: "analyst";
  status: "pending" | "approved" | "rejected";
  reviewed_by: number | null;
  created_at: string;
  reviewed_at: string | null;
}

export interface MyAccessRequest {
  id: number;
  requested_role: "analyst";
  status: "pending" | "approved" | "rejected";
  created_at: string;
  reviewed_at: string | null;
}

export async function requestAnalystAccess(): Promise<AccessRequest> {
  const response =
    await apiClient.post<AccessRequest>(
      "/users/access-requests",
    );

  return response.data;
}

export async function getMyAccessRequest(): Promise<
  MyAccessRequest | null
> {
  const response =
    await apiClient.get<MyAccessRequest | null>(
      "/users/access-requests/me",
    );

  return response.data;
}

export async function getPendingAccessRequests(): Promise<
  AccessRequest[]
> {
  const response =
    await apiClient.get<AccessRequest[]>(
      "/users/access-requests/pending",
    );

  return response.data;
}

export async function approveAccessRequest(
  requestId: number,
): Promise<AccessRequest> {
  const response =
    await apiClient.post<AccessRequest>(
      `/users/access-requests/${requestId}/approve`,
    );

  return response.data;
}

export async function rejectAccessRequest(
  requestId: number,
): Promise<AccessRequest> {
  const response =
    await apiClient.post<AccessRequest>(
      `/users/access-requests/${requestId}/reject`,
    );

  return response.data;
}
