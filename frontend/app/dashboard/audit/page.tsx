"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { fmtDate } from "@/lib/utils";

export default function AuditPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [verify, setVerify] = useState<any>(null);
  useEffect(() => { api.audit.list().then(setLogs).catch(console.error); }, []);

  const runVerify = async () => {
    const r = await api.audit.verify().catch(() => ({ valid: false, count: 0 }));
    setVerify(r);
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-slate-100">Audit Logs</h1>
        <button onClick={runVerify} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">Verify Chain</button>
      </div>
      {verify && (
        <div className={`mb-4 rounded-xl p-3 text-sm ${verify.valid ? "bg-emerald-900/30 border border-emerald-700 text-emerald-300" : "bg-red-900/30 border border-red-700 text-red-300"}`}>
          {verify.valid ? `✅ Chain valid (${verify.count} records)` : `❌ Chain broken at: ${verify.broken_at}`}
        </div>
      )}
      <Card>
        <div className="space-y-2 max-h-[70vh] overflow-y-auto">
          {logs.map(l => (
            <div key={l.id} className="flex items-start justify-between rounded-lg bg-slate-800 px-3 py-2 text-xs gap-2">
              <div className="min-w-0">
                <p className="text-slate-200 font-medium">{l.action} · <span className="text-slate-400">{l.resource_type}</span></p>
                <p className="text-slate-500">{l.actor_type}: {l.actor_id?.slice(0,8)}... · {fmtDate(l.created_at)}</p>
                {l.comment && <p className="text-slate-400 truncate mt-0.5">{l.comment}</p>}
              </div>
              <p className="font-mono text-slate-600 flex-shrink-0">{l.current_hash?.slice(0,12)}...</p>
            </div>
          ))}
          {logs.length === 0 && <p className="text-slate-500 p-4">No audit records yet</p>}
        </div>
      </Card>
    </div>
  );
}
