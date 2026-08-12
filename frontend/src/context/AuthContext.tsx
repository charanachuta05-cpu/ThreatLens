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
} from "./AuthContextDefinition";

interface AuthProviderProps {
  children: ReactNode;
}

const ACCESS_TOKEN_KEY = "access_token";
const TOKEN_TYPE_KEY = "token_type";

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

  const [loading, setLoading] =
    useState<boolean>(false);

  /*
   * Listen for unauthorized API responses.
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
   * Login
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
    } finally {
      setLoading(false);
    }
  }

  /*
   * Logout
   */
  function logout(): void {
    localStorage.removeItem(
      ACCESS_TOKEN_KEY,
    );

    localStorage.removeItem(
      TOKEN_TYPE_KEY,
    );

    setAuthenticated(false);
  }

  const value: AuthContextType = {
    authenticated,
    loading,
    login,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
