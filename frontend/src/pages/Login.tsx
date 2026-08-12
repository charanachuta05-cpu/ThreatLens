import { isAxiosError } from "axios";
import {
  useState,
  type FormEvent,
} from "react";
import { useNavigate } from "react-router-dom";

import { useAuth } from "../context/useAuth";

import "./Login.css";

function Login() {
  const navigate = useNavigate();
  const { login, loading } = useAuth();

  const [email, setEmail] =
    useState("");

  const [password, setPassword] =
    useState("");

  const [error, setError] =
    useState("");

  const [submitting, setSubmitting] =
    useState(false);

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    setError("");
    setSubmitting(true);

    try {
      await login({
        email: email.trim(),
        password,
      });

      navigate("/dashboard", {
        replace: true,
      });
    } catch (err: unknown) {
      if (
        isAxiosError<{
          detail?: string;
        }>(err)
      ) {
        const detail =
          err.response?.data?.detail;

        if (typeof detail === "string") {
          setError(detail);
        } else {
          setError(
            "Login failed. Please check your credentials.",
          );
        }
      } else if (
        err instanceof Error
      ) {
        setError(err.message);
      } else {
        setError(
          "Login failed. Please check your credentials.",
        );
      }
    } finally {
      setSubmitting(false);
    }
  }

  const isSubmitting =
    submitting || loading;

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand">
          <h1>ThreatLens</h1>

          <p>
            Threat Intelligence
            <br />
            Platform
          </p>
        </div>

        <form
          className="login-form"
          onSubmit={handleSubmit}
        >
          <div className="form-group">
            <label htmlFor="email">
              Email
            </label>

            <input
              id="email"
              type="email"
              value={email}
              onChange={(event) =>
                setEmail(
                  event.target.value,
                )
              }
              placeholder="Enter your email"
              autoComplete="email"
              required
              disabled={isSubmitting}
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">
              Password
            </label>

            <input
              id="password"
              type="password"
              value={password}
              onChange={(event) =>
                setPassword(
                  event.target.value,
                )
              }
              placeholder="Enter your password"
              autoComplete="current-password"
              required
              disabled={isSubmitting}
            />
          </div>

          {error && (
            <div
              className="login-error"
              role="alert"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            className="login-button"
            disabled={isSubmitting}
          >
            {isSubmitting
              ? "Signing in..."
              : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}

export default Login;