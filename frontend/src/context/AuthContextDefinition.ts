import { createContext } from "react";

import type { LoginRequest } from "../api/auth";

export type UserRole =
  | "admin"
  | "analyst"
  | "viewer";

export interface AuthContextType {
  authenticated: boolean;
  loading: boolean;
  role: UserRole | null;

  login: (
    credentials: LoginRequest,
  ) => Promise<void>;

  logout: () => void;
}

export const AuthContext =
  createContext<AuthContextType | undefined>(
    undefined,
  );
