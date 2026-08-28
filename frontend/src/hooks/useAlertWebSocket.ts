import { useEffect, useRef } from "react";

import type { Alert } from "../api/alerts";

interface AlertCreatedEvent {
  event: "alert.created";
  data: Alert;
}

interface AlertUpdatedEvent {
  event: "alert.updated";
  data: Alert;
}

interface AlertDeletedEvent {
  event: "alert.deleted";
  data: {
    id: number;
  };
}

type AlertWebSocketEvent =
  | AlertCreatedEvent
  | AlertUpdatedEvent
  | AlertDeletedEvent;

interface UseAlertWebSocketOptions {
  onAlertCreated?: (alert: Alert) => void;
  onAlertUpdated?: (alert: Alert) => void;
  onAlertDeleted?: (alertId: number) => void;
}

const WS_BASE_URL =
  import.meta.env.VITE_WS_BASE_URL || "ws://127.0.0.1:8000";

const ACCESS_TOKEN_KEY = "access_token";

const INITIAL_RECONNECT_DELAY = 1000;
const MAX_RECONNECT_DELAY = 10000;

export function useAlertWebSocket({
  onAlertCreated,
  onAlertUpdated,
  onAlertDeleted,
}: UseAlertWebSocketOptions) {
  const socketRef = useRef<WebSocket | null>(null);

  const reconnectTimerRef =
    useRef<ReturnType<typeof setTimeout> | null>(null);

  const reconnectDelayRef =
    useRef(INITIAL_RECONNECT_DELAY);

  const manuallyClosedRef = useRef(false);

  const callbacksRef = useRef({
    onAlertCreated,
    onAlertUpdated,
    onAlertDeleted,
  });

  useEffect(() => {
    callbacksRef.current = {
      onAlertCreated,
      onAlertUpdated,
      onAlertDeleted,
    };
  }, [
    onAlertCreated,
    onAlertUpdated,
    onAlertDeleted,
  ]);

  useEffect(() => {
    manuallyClosedRef.current = false;

    function clearReconnectTimer() {
      if (reconnectTimerRef.current !== null) {
        clearTimeout(
          reconnectTimerRef.current
        );

        reconnectTimerRef.current = null;
      }
    }

    function scheduleReconnect() {
      if (manuallyClosedRef.current) {
        return;
      }

      if (reconnectTimerRef.current !== null) {
        return;
      }

      const delay =
        reconnectDelayRef.current;

      console.info(
        `[ThreatLens] WebSocket reconnecting in ${delay}ms`
      );

      reconnectTimerRef.current =
        setTimeout(() => {
          reconnectTimerRef.current = null;

          connect();

          reconnectDelayRef.current =
            Math.min(
              reconnectDelayRef.current * 2,
              MAX_RECONNECT_DELAY
            );
        }, delay);
    }

    function connect() {
      if (manuallyClosedRef.current) {
        return;
      }

      const token = localStorage.getItem(
        ACCESS_TOKEN_KEY
      );

      if (!token) {
        console.warn(
          "[ThreatLens] WebSocket skipped: no access token."
        );

        return;
      }

      const existingSocket =
        socketRef.current;

      if (
        existingSocket &&
        (
          existingSocket.readyState ===
            WebSocket.OPEN ||
          existingSocket.readyState ===
            WebSocket.CONNECTING
        )
      ) {
        return;
      }

      const encodedToken =
        encodeURIComponent(token);

      const socket = new WebSocket(
        `${WS_BASE_URL}/ws/alerts?token=${encodedToken}`
      );

      socketRef.current = socket;

      socket.onopen = () => {
        console.info(
          "[ThreatLens] WebSocket connected."
        );

        reconnectDelayRef.current =
          INITIAL_RECONNECT_DELAY;
      };

      socket.onmessage = (event) => {
        try {
          const message =
            JSON.parse(
              event.data
            ) as AlertWebSocketEvent;

          switch (message.event) {
            case "alert.created":
              callbacksRef.current
                .onAlertCreated?.(
                  message.data
                );
              break;

            case "alert.updated":
              callbacksRef.current
                .onAlertUpdated?.(
                  message.data
                );
              break;

            case "alert.deleted":
              callbacksRef.current
                .onAlertDeleted?.(
                  message.data.id
                );
              break;

            default:
              console.warn(
                "[ThreatLens] Unknown WebSocket event:",
                message
              );
          }
        } catch (error) {
          console.error(
            "[ThreatLens] Failed to parse WebSocket message:",
            error
          );
        }
      };

      socket.onerror = (error) => {
        console.error(
          "[ThreatLens] WebSocket error:",
          error
        );
      };

      socket.onclose = () => {
        console.warn(
          "[ThreatLens] WebSocket disconnected."
        );

        if (
          socketRef.current === socket
        ) {
          socketRef.current = null;
        }

        scheduleReconnect();
      };
    }

    connect();

    return () => {
      manuallyClosedRef.current = true;

      clearReconnectTimer();

      const socket =
        socketRef.current;

      socketRef.current = null;

      if (socket) {
        socket.close();
      }
    };
  }, []);
}