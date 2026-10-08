"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { fmtDate } from "@/lib/utils";

export default function ApprovalsPage() {
  const [approvals, setApprovals] = useState<any[]>([]);
  const [msg, setMsg] = useState("");
  const load = () => api.approvals.list().then(setApprovals).catch(console.error);
  useEffect(() => { load(); }, []);

  const act = async (id: string, action: "approve"|"reject") => {
    try {
      await (action === "approve" ? api.approvals.approve(id) : api.approvals.reject(id));
      setMsg(`Approval ${action}d successfully`);
      load();
    } catch (e: any) { setMsg(e.message); }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold text-slate-100 mb-6">Approval Queue</h1>
      {msg && <div className="mb-4 rounded-lg bg-slate-800 px-4 py-2 text-sm text-slate-300">{msg}</div>}
      <div className="space-y-4">
        {approvals.map(a => (
          <Card key={a.id}>
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1"><Badge label={a.status.toUpperCase()} /><span className="text-xs text-slate-500">Expires: {fmtDate(a.expires_at)}</span></div>
                <p className="text-xs text-slate-400 font-mono">Request: {a.request_id}</p>
              </div>
              {a.status === "pending" && (
                <div className="flex gap-2">
                  <button onClick={() => act(a.id, "approve")} className="rounded-lg bg-emerald-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-600">Approve</button>
                  <button onClick={() => act(a.id, "reject")} className="rounded-lg bg-red-800 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700">Reject</button>
                </div>
              )}
            </div>
          </Card>
        ))}
        {approvals.length === 0 && <Card><p className="text-slate-500">No approvals</p></Card>}
      </div>
    </div>
  );
}
