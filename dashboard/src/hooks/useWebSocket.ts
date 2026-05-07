import { useCallback, useEffect, useRef, useState } from "react";
import type { WsEvent } from "@/types/api";

/** Maximum number of events kept in the message buffer. */
const MAX_MESSAGES = 200;

/** Initial reconnect delay in milliseconds. */
const INITIAL_RECONNECT_DELAY = 1_000;

/** Maximum reconnect delay in milliseconds. */
const MAX_RECONNECT_DELAY = 30_000;

/** Backoff multiplier applied after each failed reconnection attempt. */
const BACKOFF_FACTOR = 2;

export interface UseWebSocketReturn {
  /** Whether the WebSocket is currently connected. */
  connected: boolean;
  /** Rolling buffer of received events (newest last). */
  messages: WsEvent[];
  /** The most recently received event, or null if none. */
  lastEvent: WsEvent | null;
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

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectDelay = useRef(INITIAL_RECONNECT_DELAY);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;

    // Build the WebSocket URL from the current page origin.
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/live`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.addEventListener("open", () => {
      if (!mountedRef.current) return;
      setConnected(true);
      reconnectDelay.current = INITIAL_RECONNECT_DELAY;
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

  return { connected, messages, lastEvent };
}
