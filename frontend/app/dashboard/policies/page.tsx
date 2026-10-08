"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<any[]>([]);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", priority: 10, default_action: "REQUIRE_APPROVAL" });
  const load = () => api.policies.list().then(setPolicies).catch(console.error);
  useEffect(() => { load(); }, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    await api.policies.create(form).catch(console.error);
    setCreating(false); load();
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-slate-100">Policies</h1>
        <button onClick={() => setCreating(!creating)} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">+ New Policy</button>
      </div>
      {creating && (
        <Card className="mb-6">
          <CardHeader><CardTitle>Create Policy</CardTitle></CardHeader>
          <form onSubmit={create} className="grid grid-cols-2 gap-3">
            <input placeholder="Name" value={form.name} onChange={e => setForm({...form, name: e.target.value})}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100 text-sm col-span-2" required />
            <input placeholder="Description" value={form.description} onChange={e => setForm({...form, description: e.target.value})}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100 text-sm col-span-2" />
            <input type="number" placeholder="Priority" value={form.priority} onChange={e => setForm({...form, priority: +e.target.value})}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100 text-sm" />
            <select value={form.default_action} onChange={e => setForm({...form, default_action: e.target.value})}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100 text-sm">
              <option>ALLOW</option><option>BLOCK</option><option>REQUIRE_APPROVAL</option>
            </select>
            <div className="col-span-2 flex gap-2">
              <button type="submit" className="rounded-lg bg-emerald-700 px-4 py-2 text-sm text-white hover:bg-emerald-600">Create</button>
              <button type="button" onClick={() => setCreating(false)} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300">Cancel</button>
            </div>
          </form>
        </Card>
      )}
      <div className="space-y-3">
        {policies.map(p => (
          <Card key={p.id}>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-slate-100">{p.name}</p>
                <p className="text-xs text-slate-500">{p.description || "No description"} · Priority: {p.priority} · v{p.current_version}</p>
              </div>
              <div className="flex items-center gap-3">
                <Badge label={p.default_action} />
                <span className={`text-xs ${p.is_active ? "text-emerald-400" : "text-slate-500"}`}>{p.is_active ? "Active" : "Disabled"}</span>
                <button onClick={() => api.policies.toggle(p.id).then(load)} className="text-xs text-blue-400 hover:text-blue-300">Toggle</button>
                <button onClick={() => api.policies.del(p.id).then(load)} className="text-xs text-red-400 hover:text-red-300">Delete</button>
              </div>
            </div>
          </Card>
        ))}
        {policies.length === 0 && <Card><p className="text-slate-500">No custom policies. Default policy engine rules apply.</p></Card>}
      </div>
    </div>
  );
}
