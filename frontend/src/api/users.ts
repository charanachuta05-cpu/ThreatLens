import apiClient from "./client";

export interface AssignableUser {
  id: number;
  username: string;
  email: string;
  role: "admin" | "analyst" | "viewer";
  is_active: boolean;
  created_at: string;
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
