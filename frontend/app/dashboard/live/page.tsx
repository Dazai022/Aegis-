"use client";
import { useState } from "react";
import { useRealtime } from "@/hooks/useRealtime";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface LiveEvent {
  id: number;
  topic: string;
  payload: Record<string, any>;
  ts: number;
}

const topicColor: Record<string, string> = {
  "requests.new": "bg-blue-900 text-blue-300 border-blue-700",
  "requests.decision": "bg-purple-900 text-purple-300 border-purple-700",
  "requests.blocked": "bg-red-900 text-red-300 border-red-700",
  "approvals.requested": "bg-amber-900 text-amber-300 border-amber-700",
  "approvals.completed": "bg-emerald-900 text-emerald-300 border-emerald-700",
  "execution.started": "bg-cyan-900 text-cyan-300 border-cyan-700",
  "execution.completed": "bg-emerald-900 text-emerald-300 border-emerald-700",
  "execution.failed": "bg-red-900 text-red-300 border-red-700",
};

export default function LivePage() {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [count, setCount] = useState(0);
  const connected = useRealtime((ev) => {
    if (ev.type === "ping") return;
    setCount(c => c + 1);
    setEvents(prev => [{ id: Date.now(), topic: ev.topic || "unknown", payload: ev.payload || ev, ts: ev.ts || Date.now() / 1000 }, ...prev].slice(0, 100));
  });

  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <h1 className="text-2xl font-bold text-slate-100">Live Security Events</h1>
        <span className={`flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${connected ? "bg-emerald-900 text-emerald-300" : "bg-slate-800 text-slate-400"}`}>
          <span className={`h-2 w-2 rounded-full ${connected ? "bg-emerald-400 animate-pulse" : "bg-slate-500"}`} />
          {connected ? "Connected" : "Disconnected"}
        </span>
        <span className="text-xs text-slate-500">{count} events received</span>
      </div>
      <div className="grid grid-cols-1 gap-3 max-h-[80vh] overflow-y-auto">
        {events.map(ev => (
          <Card key={ev.id} className="py-3 px-4">
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${topicColor[ev.topic] || "bg-slate-700 text-slate-300 border-slate-600"}`}>
                    {ev.topic}
                  </span>
                  <span className="text-xs text-slate-500">{new Date(ev.ts * 1000).toLocaleTimeString()}</span>
                </div>
                <pre className="text-xs text-slate-400 overflow-x-auto whitespace-pre-wrap break-all">
                  {JSON.stringify(ev.payload, null, 2).slice(0, 300)}
                </pre>
              </div>
            </div>
          </Card>
        ))}
        {events.length === 0 && (
          <Card>
            <p className="text-slate-500 text-sm">No events yet. Events will appear here in real-time as agents make requests.</p>
            <p className="text-slate-600 text-xs mt-2">Try submitting a request via POST /v1/execute to see events flow through.</p>
          </Card>
        )}
      </div>
    </div>
  );
}

