"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { fmtDate } from "@/lib/utils";

export default function RequestsPage() {
  const [requests, setRequests] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  useEffect(() => { api.requests.list().then(setRequests).catch(console.error); }, []);

  const loadDetail = async (id: string) => {
    const r = await api.requests.get(id).catch(() => null);
    setSelected(r);
  };

  return (
    <div>
      <h1 className="text-2xl font-bold text-slate-100 mb-6">Execution Requests</h1>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Card>
            <div className="space-y-2 max-h-[70vh] overflow-y-auto">
              {requests.map(r => (
                <button key={r.id} onClick={() => loadDetail(r.id)}
                  className="w-full text-left flex items-center justify-between rounded-lg bg-slate-800 hover:bg-slate-700 px-3 py-2 text-sm transition-colors">
                  <div>
                    <p className="text-slate-200 font-medium">{r.tool_name}</p>
                    <p className="text-slate-500 text-xs font-mono">{r.id?.slice(0,16)}...</p>
                    <p className="text-slate-500 text-xs">{fmtDate(r.created_at)}</p>
                  </div>
                  <Badge label={r.state?.toUpperCase() || ""} />
                </button>
              ))}
              {requests.length === 0 && <p className="text-slate-500 text-sm p-4">No requests yet</p>}
            </div>
          </Card>
        </div>
        <div>
          {selected ? (
            <Card>
              <CardHeader><CardTitle>Request Detail</CardTitle></CardHeader>
              <div className="space-y-3 text-sm">
                <div><p className="text-slate-500">Tool</p><p className="text-slate-200 font-medium">{selected.tool}</p></div>
                <div><p className="text-slate-500">State</p><Badge label={(selected.state || "").toUpperCase()} /></div>
                {selected.decision && (<>
                  <div><p className="text-slate-500">Decision</p><Badge label={selected.decision.action} /></div>
                  <div><p className="text-slate-500">Reason</p><p className="text-slate-300 text-xs">{selected.decision.reason}</p></div>
                </>)}
                {selected.risk && (<>
                  <div><p className="text-slate-500">Risk Score</p><p className="text-slate-200 font-bold">{selected.risk.score}/100 — {selected.risk.level}</p></div>
                  {selected.risk.signals?.filter((s: any) => s.triggered).map((s: any) => (
                    <div key={s.name} className="rounded bg-slate-800 px-2 py-1">
                      <p className="text-xs font-medium text-orange-400">{s.name} (+{s.weight})</p>
                      <p className="text-xs text-slate-400">{s.reason}</p>
                    </div>
                  ))}
                </>)}
              </div>
            </Card>
          ) : <Card><p className="text-slate-500 text-sm">Select a request to see details</p></Card>}
        </div>
      </div>
    </div>
  );
}
