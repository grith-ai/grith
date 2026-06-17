import { useCallback, useEffect, useRef, useState } from "react";
import type { WsEvent } from "@/types/api";
import { getDashboardCsrfValue } from "@/lib/csrf";

/** Maximum number of events kept in the message buffer. */
const MAX_MESSAGES = 200;

/** Initial reconnect delay in milliseconds. */
const INITIAL_RECONNECT_DELAY = 1_000;

/** Maximum reconnect delay in milliseconds. */
const MAX_RECONNECT_DELAY = 30_000;

/** Backoff multiplier applied after each failed reconnection attempt. */
const BACKOFF_FACTOR = 2;

/**
 * Consecutive connection attempts that close without ever opening before the
 * feed is reported as unavailable. The most likely cause is a missing/stale
 * dashboard token (the upgrade is rejected with 401, which browsers surface
 * only as a generic close), so we surface a hint without giving up — a later
 * reconnect re-reads the token from localStorage and self-heals.
 */
const FAILED_ATTEMPTS_BEFORE_DEGRADED = 4;

export interface UseWebSocketReturn {
  /** Whether the WebSocket is currently connected. */
  connected: boolean;
  /** Rolling buffer of received events (newest last). */
  messages: WsEvent[];
  /** The most recently received event, or null if none. */
  lastEvent: WsEvent | null;
  /**
   * True after repeated handshakes failed to open — typically a missing or
   * stale dashboard token. The feed keeps retrying; re-opening the dashboard
   * via the URL grith printed (which carries the `#token=` fragment) fixes it.
   */
  liveFeedUnavailable: boolean;
}

/**
 * Hook that connects to the grith live WebSocket feed at `/ws/live`.
 *
 * Automatically reconnects with exponential backoff on disconnection.
 * All incoming messages are parsed as typed `WsEvent` objects.
 */
export function useWebSocket(): UseWebSocketReturn {
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<WsEvent[]>([]);
  const [lastEvent, setLastEvent] = useState<WsEvent | null>(null);
  const [liveFeedUnavailable, setLiveFeedUnavailable] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectDelay = useRef(INITIAL_RECONNECT_DELAY);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);
  const failedAttempts = useRef(0);
  const openedSinceConnect = useRef(false);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;

    openedSinceConnect.current = false;

    // Build the WebSocket URL from the current page origin. Browsers can't set
    // custom WS request headers, so the dashboard token travels as a query
    // parameter (the server also enforces an Origin-vs-Host check). The token
    // is re-read on every (re)connect, so updating it (e.g. opening the
    // tokenised URL in another tab) lets an unavailable feed self-heal.
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const token = encodeURIComponent(getDashboardCsrfValue());
    const wsUrl = `${protocol}//${window.location.host}/ws/live?token=${token}`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.addEventListener("open", () => {
      if (!mountedRef.current) return;
      setConnected(true);
      reconnectDelay.current = INITIAL_RECONNECT_DELAY;
      failedAttempts.current = 0;
      openedSinceConnect.current = true;
      setLiveFeedUnavailable(false);
    });

    ws.addEventListener("message", (event: MessageEvent) => {
      if (!mountedRef.current) return;

      try {
        const parsed = JSON.parse(event.data as string) as WsEvent;
        setLastEvent(parsed);
        setMessages((prev) => {
          const next = [...prev, parsed];
          return next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next;
        });
      } catch {
        // Ignore malformed messages.
      }
    });

    ws.addEventListener("close", () => {
      if (!mountedRef.current) return;
      setConnected(false);
      // A close without a prior open is a failed handshake (likely auth).
      // After several in a row, surface the degraded state — but keep retrying.
      if (!openedSinceConnect.current) {
        failedAttempts.current += 1;
        if (failedAttempts.current >= FAILED_ATTEMPTS_BEFORE_DEGRADED) {
          setLiveFeedUnavailable(true);
        }
      }
      scheduleReconnect();
    });

    ws.addEventListener("error", () => {
      // The close handler will fire after an error, so we just ensure the
      // socket is cleaned up.
      ws.close();
    });
  }, []);

  const scheduleReconnect = useCallback(() => {
    if (!mountedRef.current) return;
    if (reconnectTimer.current) clearTimeout(reconnectTimer.current);

    reconnectTimer.current = setTimeout(() => {
      reconnectDelay.current = Math.min(
        reconnectDelay.current * BACKOFF_FACTOR,
        MAX_RECONNECT_DELAY,
      );
      connect();
    }, reconnectDelay.current);
  }, [connect]);

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  return { connected, messages, lastEvent, liveFeedUnavailable };
}
