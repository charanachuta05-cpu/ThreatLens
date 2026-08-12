import { createContext } from "react";

import type { LoginRequest } from "../api/auth";

export interface AuthContextType {
  authenticated: boolean;
  loading: boolean;
  login: (
    credentials: LoginRequest,
  ) => Promise<void>;
  logout: () => void;
}

export const AuthContext =
  createContext<AuthContextType | undefined>(
    undefined,
  );
