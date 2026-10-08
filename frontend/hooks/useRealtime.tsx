"use client";
import { useEffect, useRef, useState } from "react";
import { getToken } from "@/lib/api";

const WS_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace("http","ws");

export function useRealtime(onEvent: (ev: any) => void) {
  const ws = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    const token = getToken();
    if (!token) return;
    const connect = () => {
      const w = new WebSocket(`${WS_URL}/ws/events?token=${token}`);
      ws.current = w;
      w.onopen = () => setConnected(true);
      w.onclose = () => { setConnected(false); setTimeout(connect, 3000); };
      w.onmessage = (e) => { try { onEvent(JSON.parse(e.data)); } catch {} };
    };
    connect();
    return () => { ws.current?.close(); };
  }, []);
  return connected;
}

