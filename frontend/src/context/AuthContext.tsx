import {
  useEffect,
  useState,
  type ReactNode,
} from "react";

import {
  loginUser,
  type LoginRequest,
} from "../api/auth";

import {
  AuthContext,
  type AuthContextType,
  type UserRole,
} from "./AuthContextDefinition";

interface AuthProviderProps {
  children: ReactNode;
}

interface JwtPayload {
  role?: string;
}

const ACCESS_TOKEN_KEY = "access_token";
const TOKEN_TYPE_KEY = "token_type";

function getRoleFromToken(
  token: string | null,
): UserRole | null {
  if (!token) {
    return null;
  }

  try {
    const parts = token.split(".");

    if (parts.length !== 3) {
      return null;
    }

    const encodedPayload = parts[1];

    const normalizedPayload =
      encodedPayload
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    const paddedPayload =
      normalizedPayload.padEnd(
        Math.ceil(
          normalizedPayload.length / 4,
        ) * 4,
        "=",
      );

    const payload = JSON.parse(
      atob(paddedPayload),
    ) as JwtPayload;

    const role = payload.role
      ?.trim()
      .toLowerCase();

    if (
      role === "admin" ||
      role === "analyst" ||
      role === "viewer"
    ) {
      return role;
    }

    return null;
  } catch {
    return null;
  }
}

function getStoredRole(): UserRole | null {
  return getRoleFromToken(
    localStorage.getItem(
      ACCESS_TOKEN_KEY,
    ),
  );
}

export function AuthProvider({
  children,
}: AuthProviderProps) {
  const [authenticated, setAuthenticated] =
    useState<boolean>(() =>
      Boolean(
        localStorage.getItem(
          ACCESS_TOKEN_KEY,
        ),
      ),
    );

  const [role, setRole] =
    useState<UserRole | null>(
      getStoredRole,
    );

  const [loading, setLoading] =
    useState<boolean>(false);

  /*
   * Handle unauthorized API responses.
   */
  useEffect(() => {
    function handleUnauthorized() {
      localStorage.removeItem(
        ACCESS_TOKEN_KEY,
      );

      localStorage.removeItem(
        TOKEN_TYPE_KEY,
      );

      setAuthenticated(false);
      setRole(null);
    }

    window.addEventListener(
      "auth:unauthorized",
      handleUnauthorized,
    );

    return () => {
      window.removeEventListener(
        "auth:unauthorized",
        handleUnauthorized,
      );
    };
  }, []);

  /*
   * Login.
   */
  async function login(
    credentials: LoginRequest,
  ): Promise<void> {
    setLoading(true);

    try {
      const data =
        await loginUser(credentials);

      if (!data.access_token) {
        throw new Error(
          "Login succeeded but no access token was returned.",
        );
      }

      localStorage.setItem(
        ACCESS_TOKEN_KEY,
        data.access_token,
      );

      localStorage.setItem(
        TOKEN_TYPE_KEY,
        data.token_type || "bearer",
      );

      setAuthenticated(true);

      setRole(
        getRoleFromToken(
          data.access_token,
        ),
      );
    } finally {
      setLoading(false);
    }
  }

  /*
   * Logout.
   */
  function logout(): void {
    localStorage.removeItem(
      ACCESS_TOKEN_KEY,
    );

    localStorage.removeItem(
      TOKEN_TYPE_KEY,
    );

    setAuthenticated(false);
    setRole(null);
  }

  const value: AuthContextType = {
    authenticated,
    loading,
    role,
    login,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
