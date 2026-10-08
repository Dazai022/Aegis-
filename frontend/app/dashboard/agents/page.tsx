"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function AgentsPage() {
  const [agents, setAgents] = useState<any[]>([]);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [newKey, setNewKey] = useState<{ key: string; agentId: string } | null>(null);
  const [msg, setMsg] = useState("");
  const load = () => api.agents.list().then(setAgents).catch(console.error);
  useEffect(() => { load(); }, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const r = await api.agents.create({ display_name: name });
      setNewKey({ key: r.plaintext_key, agentId: r.id });
      setCreating(false); setName(""); load();
    } catch (e: any) { setMsg(e.message); }
  };

  const revoke = async (id: string) => {
    await api.agents.revoke(id).catch(() => {});
    load();
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-slate-100">Agents</h1>
        <button onClick={() => setCreating(!creating)} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">+ New Agent</button>
      </div>
      {newKey && (
        <div className="mb-6 rounded-xl border border-amber-700 bg-amber-900/30 p-4">
          <p className="text-amber-300 font-semibold mb-2">⚠ Copy your API key — it will NOT be shown again</p>
          <code className="block rounded bg-slate-900 px-3 py-2 text-sm text-emerald-400 font-mono break-all">{newKey.key}</code>
          <button onClick={() => setNewKey(null)} className="mt-2 text-xs text-slate-400 hover:text-slate-200">Dismiss</button>
        </div>
      )}
      {creating && (
        <Card className="mb-6">
          <CardHeader><CardTitle>Create Agent</CardTitle></CardHeader>
          <form onSubmit={create} className="flex gap-3">
            <input value={name} onChange={e => setName(e.target.value)} placeholder="Agent display name"
              className="flex-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100 text-sm" required />
            <button type="submit" className="rounded-lg bg-emerald-700 px-4 py-2 text-sm text-white hover:bg-emerald-600">Create</button>
          </form>
          {msg && <p className="mt-2 text-sm text-red-400">{msg}</p>}
        </Card>
      )}
      <div className="space-y-3">
        {agents.map(a => (
          <Card key={a.id}>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-slate-100">{a.display_name}</p>
                <p className="text-xs text-slate-500 font-mono">{a.id}</p>
              </div>
              <div className="flex items-center gap-3">
                <Badge label={a.status.toUpperCase()} />
                {a.status === "active" && <button onClick={() => revoke(a.id)} className="text-xs text-red-400 hover:text-red-300">Revoke</button>}
              </div>
            </div>
          </Card>
        ))}
        {agents.length === 0 && <Card><p className="text-slate-500">No agents yet</p></Card>}
      </div>
    </div>
  );
}
