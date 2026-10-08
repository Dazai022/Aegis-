"use client";
import { useEffect, useState, useCallback } from "react";
import { api } from "@/lib/api";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useRealtime } from "@/hooks/useRealtime";
import { fmtDate, riskColor } from "@/lib/utils";

function StatCard({ label, value, icon, color = "text-blue-400" }: any) {
  return (
    <Card className="flex items-center gap-4">
      <div>
        <p className="text-xs text-slate-500 uppercase tracking-wider">{label}</p>
        <p className={`mt-1 text-3xl font-bold ${color}`}>{value}</p>
      </div>
      <span className="ml-auto text-3xl opacity-40">{icon}</span>
    </Card>
  );
}

export default function DashboardPage() {
  const [requests, setRequests] = useState<any[]>([]);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const [reqs, apps] = await Promise.all([api.requests.list(), api.approvals.list()]);
      setRequests(reqs);
      setApprovals(apps);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);
  const connected = useRealtime((ev) => {
    if (ev.topic?.startsWith("requests.") || ev.topic?.startsWith("approvals.")) load();
  });

  const total = requests.length;
  const allowed = requests.filter(r => r.state === "decided" || r.state === "succeeded").length;
  const blocked = requests.filter(r => r.state === "blocked").length;
  const pending = approvals.filter(a => a.status === "pending").length;
  const pendingApprovalReqs = requests.filter(r => r.state === "approval_pending").length;

  const decisionDist: Record<string, number> = {};
  requests.forEach(r => { decisionDist[r.state] = (decisionDist[r.state] || 0) + 1; });

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-slate-100">Security Overview</h1>
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${connected ? "bg-emerald-400 animate-pulse" : "bg-slate-600"}`} />
          <span className="text-xs text-slate-500">{connected ? "Live" : "Offline"}</span>
        </div>
      </div>

      {loading ? <p className="text-slate-400">Loading...</p> : (<>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <StatCard label="Total Requests" value={total} icon="📊" color="text-blue-400" />
          <StatCard label="Allowed" value={allowed} icon="✅" color="text-emerald-400" />
          <StatCard label="Blocked" value={blocked} icon="🚫" color="text-red-400" />
          <StatCard label="Pending Approval" value={pending + pendingApprovalReqs} icon="⏳" color="text-amber-400" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <Card>
              <CardHeader><CardTitle>Recent Execution Requests</CardTitle></CardHeader>
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {requests.slice(0, 15).map(r => (
                  <div key={r.id} className="flex items-center justify-between rounded-lg bg-slate-800 px-3 py-2 text-sm">
                    <div className="min-w-0 flex-1">
                      <p className="text-slate-200 font-medium truncate">{r.tool_name}</p>
                      <p className="text-slate-500 text-xs">{fmtDate(r.created_at)}</p>
                    </div>
                    <Badge label={(r.state || "").toUpperCase().replace("_", " ")} />
                  </div>
                ))}
                {requests.length === 0 && <p className="text-slate-500 text-sm p-2">No requests yet — submit one via POST /v1/execute</p>}
              </div>
            </Card>
          </div>
          <div className="space-y-4">
            <Card>
              <CardHeader><CardTitle>Decision Distribution</CardTitle></CardHeader>
              <div className="space-y-2">
                {Object.entries(decisionDist).map(([state, count]) => (
                  <div key={state} className="flex items-center justify-between">
                    <span className="text-xs text-slate-400 capitalize">{state.replace("_", " ")}</span>
                    <div className="flex items-center gap-2">
                      <div className="h-2 rounded-full bg-blue-600" style={{ width: `${Math.max(4, (count / total) * 80)}px` }} />
                      <span className="text-xs font-mono text-slate-300 w-5 text-right">{count}</span>
                    </div>
                  </div>
                ))}
                {total === 0 && <p className="text-slate-500 text-xs">No data yet</p>}
              </div>
            </Card>
            <Card>
              <CardHeader><CardTitle>Pending Approvals</CardTitle></CardHeader>
              <div className="space-y-2 max-h-40 overflow-y-auto">
                {approvals.filter(a => a.status === "pending").map(a => (
                  <div key={a.id} className="rounded-lg bg-slate-800 px-3 py-2 text-xs">
                    <p className="text-amber-300 font-medium">Awaiting approval</p>
                    <p className="text-slate-500 font-mono truncate">{a.request_id?.slice(0, 20)}...</p>
                    <p className="text-slate-600">Expires: {fmtDate(a.expires_at)}</p>
                  </div>
                ))}
                {approvals.filter(a => a.status === "pending").length === 0 && <p className="text-slate-500 text-xs">No pending approvals</p>}
              </div>
            </Card>
          </div>
        </div>
      </>)}
    </div>
  );
}

