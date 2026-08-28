import apiClient from "./client";

export interface LoginRequest {
  email: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

export async function loginUser(
  credentials: LoginRequest
): Promise<TokenResponse> {
  const response = await apiClient.post<TokenResponse>(
    "/auth/login",
    credentials
  );

  return response.data;
}
export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
}

export interface RegisteredUser {
  id: number;
  username: string;
  email: string;
  role: "admin" | "analyst" | "viewer";
  is_active: boolean;
  created_at: string;
}

export async function registerUser(
  user: RegisterRequest,
): Promise<RegisteredUser> {
  const response = await apiClient.post<RegisteredUser>(
    "/auth/register",
    user,
  );

  return response.data;
}
