import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

import {
  loginUser,
  type LoginRequest,
} from "../api/auth";

interface AuthContextType {
  authenticated: boolean;
  loading: boolean;
  login: (credentials: LoginRequest) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(
  undefined
);

interface AuthProviderProps {
  children: ReactNode;
}

const ACCESS_TOKEN_KEY = "access_token";
const TOKEN_TYPE_KEY = "token_type";

export function AuthProvider({
  children,
}: AuthProviderProps) {
  const [authenticated, setAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);

    setAuthenticated(Boolean(token));
    setLoading(false);
  }, []);

  async function login(
    credentials: LoginRequest
  ): Promise<void> {
    const data = await loginUser(credentials);

    if (!data.access_token) {
      throw new Error("Login succeeded but no access token was returned.");
    }

    localStorage.setItem(
      ACCESS_TOKEN_KEY,
      data.access_token
    );

    localStorage.setItem(
      TOKEN_TYPE_KEY,
      data.token_type || "bearer"
    );

    setAuthenticated(true);
  }

  function logout(): void {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(TOKEN_TYPE_KEY);

    setAuthenticated(false);
  }

  return (
    <AuthContext.Provider
      value={{
        authenticated,
        loading,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error(
      "useAuth must be used inside AuthProvider"
    );
  }

  return context;
}