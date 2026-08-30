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