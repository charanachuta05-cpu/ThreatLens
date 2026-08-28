import { isAxiosError } from "axios";
import {
  useState,
  type FormEvent,
} from "react";
import {
  Link,
  useNavigate,
} from "react-router-dom";

import { registerUser } from "../api/auth";

import "./Login.css";

function Register() {
  const navigate = useNavigate();

  const [username, setUsername] =
    useState("");

  const [email, setEmail] =
    useState("");

  const [password, setPassword] =
    useState("");

  const [
    confirmPassword,
    setConfirmPassword,
  ] = useState("");

  const [error, setError] =
    useState("");

  const [submitting, setSubmitting] =
    useState(false);

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    setError("");

    const normalizedUsername =
      username.trim();

    const normalizedEmail =
      email.trim();

    if (!normalizedUsername) {
      setError("Username is required.");
      return;
    }

    if (!normalizedEmail) {
      setError("Email is required.");
      return;
    }

    if (password.length < 8) {
      setError(
        "Password must contain at least 8 characters.",
      );
      return;
    }

    if (password !== confirmPassword) {
      setError(
        "Passwords do not match.",
      );
      return;
    }

    setSubmitting(true);

    try {
      await registerUser({
        username: normalizedUsername,
        email: normalizedEmail,
        password,
      });

      navigate("/login", {
        replace: true,
        state: {
          message:
            "Account created successfully. Please sign in.",
        },
      });
    } catch (err: unknown) {
      if (
        isAxiosError<{
          detail?: string;
        }>(err)
      ) {
        const detail =
          err.response?.data?.detail;

        if (
          typeof detail === "string"
        ) {
          setError(detail);
        } else {
          setError(
            "Unable to create account. Please check your details.",
          );
        }
      } else if (
        err instanceof Error
      ) {
        setError(err.message);
      } else {
        setError(
          "Unable to create account. Please try again.",
        );
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand">
          <h1>ThreatLens</h1>

          <p>
            Create your
            <br />
            Threat Intelligence account
          </p>
        </div>

        <form
          className="login-form"
          onSubmit={handleSubmit}
        >
          <div className="form-group">
            <label htmlFor="username">
              Username
            </label>

            <input
              id="username"
              type="text"
              value={username}
              onChange={(event) =>
                setUsername(
                  event.target.value,
                )
              }
              placeholder="Enter username"
              autoComplete="username"
              required
              disabled={submitting}
            />
          </div>

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
              disabled={submitting}
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
              placeholder="Minimum 8 characters"
              autoComplete="new-password"
              minLength={8}
              required
              disabled={submitting}
            />
          </div>

          <div className="form-group">
            <label htmlFor="confirm-password">
              Confirm Password
            </label>

            <input
              id="confirm-password"
              type="password"
              value={confirmPassword}
              onChange={(event) =>
                setConfirmPassword(
                  event.target.value,
                )
              }
              placeholder="Confirm your password"
              autoComplete="new-password"
              minLength={8}
              required
              disabled={submitting}
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
            disabled={submitting}
          >
            {submitting
              ? "Creating account..."
              : "Create Account"}
          </button>
        </form>

        <div
          style={{
            marginTop: "18px",
            textAlign: "center",
            color: "#94a3b8",
            fontSize: "14px",
          }}
        >
          Already have an account?{" "}
          <Link
            to="/login"
            style={{
              color: "#60a5fa",
              textDecoration: "none",
              fontWeight: 600,
            }}
          >
            Sign In
          </Link>
        </div>
      </div>
    </div>
  );
}

export default Register;
