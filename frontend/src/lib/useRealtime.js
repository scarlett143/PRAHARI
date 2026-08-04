import { useEffect, useRef, useState } from "react";
import { getApiUrl, getToken } from "./api.js";

/**
 * Authenticated WebSocket with exponential backoff.
 *
 * The server closes with 1013 ("try again later") when the connection cap is
 * reached, and 4401/4403 for auth problems. Only the former is worth retrying
 * aggressively -- retrying a rejected token in a tight loop just burns the
 * server's time, so those close codes stop the loop.
 */
export function useRealtime(enabled) {
  const [event, setEvent] = useState(null);
  const [status, setStatus] = useState("idle");
  const socketRef = useRef(null);
  const attemptRef = useRef(0);
  const timerRef = useRef(null);
  const closedRef = useRef(false);

  useEffect(() => {
    if (!enabled) {
      setStatus("idle");
      return undefined;
    }

    closedRef.current = false;

    function connect() {
      const token = getToken();
      if (!token) return;

      const url = `${getApiUrl().replace(/^http/, "ws")}/ws?token=${encodeURIComponent(token)}`;
      const socket = new WebSocket(url);
      socketRef.current = socket;
      setStatus("connecting");

      socket.onopen = () => {
        attemptRef.current = 0;
        setStatus("open");
      };

      socket.onmessage = (message) => {
        try {
          setEvent({ ...JSON.parse(message.data), receivedAt: Date.now() });
        } catch {
          /* a frame we do not understand is not worth tearing the link down for */
        }
      };

      socket.onclose = (closeEvent) => {
        if (closedRef.current) return;
        setStatus("closed");
        // 4401/4403 are authentication verdicts; reconnecting cannot change them.
        if (closeEvent.code === 4401 || closeEvent.code === 4403) return;

        attemptRef.current += 1;
        const delay = Math.min(1000 * 2 ** (attemptRef.current - 1), 30000);
        timerRef.current = setTimeout(connect, delay);
      };

      socket.onerror = () => setStatus("error");
    }

    connect();

    // A periodic frame keeps intermediaries from reaping an idle link.
    const keepalive = setInterval(() => {
      if (socketRef.current?.readyState === WebSocket.OPEN) {
        socketRef.current.send("ping");
      }
    }, 25000);

    return () => {
      closedRef.current = true;
      clearInterval(keepalive);
      if (timerRef.current) clearTimeout(timerRef.current);
      socketRef.current?.close();
    };
  }, [enabled]);

  return { event, status };
}
