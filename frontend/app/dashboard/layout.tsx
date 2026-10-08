"use client";
import Link from "next/link";
import { useRouter, usePathname } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { useEffect } from "react";

const nav = [
  { href: "/dashboard", label: "Overview", icon: "\u26a1" },
  { href: "/dashboard/requests", label: "Requests", icon: "\ud83d\udccb" },
  { href: "/dashboard/agents", label: "Agents", icon: "\ud83e\udd16" },
  { href: "/dashboard/policies", label: "Policies", icon: "\ud83d\udcdc" },
  { href: "/dashboard/approvals", label: "Approvals", icon: "\u2705" },
  { href: "/dashboard/audit", label: "Audit Logs", icon: "\ud83d\udd0d" },
  { href: "/dashboard/live", label: "Live Events", icon: "\ud83d\udce1" },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, loading, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  useEffect(() => { if (!loading && !user) router.push("/login"); }, [user, loading]);
  if (loading) return <div className="flex h-screen items-center justify-center text-slate-400">Loading...</div>;
  if (!user) return null;
  return (
    <div className="flex h-screen bg-[#0a0a0f]">
      <aside className="w-56 flex-shrink-0 border-r border-slate-800 bg-slate-950 flex flex-col">
        <div className="p-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <span className="text-2xl">\ud83d\udee1\ufe0f</span>
            <div><p className="font-bold text-slate-100 text-sm">Aegis</p><p className="text-xs text-slate-500">Security Gateway</p></div>
          </div>
        </div>
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {nav.map(n => (
            <Link key={n.href} href={n.href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${pathname === n.href ? "bg-blue-600 text-white" : "text-slate-400 hover:bg-slate-800 hover:text-slate-100"}`}>
              <span>{n.icon}</span>{n.label}
            </Link>
          ))}
        </nav>
        <div className="p-3 border-t border-slate-800">
          <p className="text-xs text-slate-500 truncate mb-1">{user.email}</p>
          <p className="text-xs text-slate-600 mb-2">{user.role}</p>
          <button onClick={() => { logout(); router.push("/login"); }} className="text-xs text-red-400 hover:text-red-300">Sign out</button>
        </div>
      </aside>
      <main className="flex-1 overflow-auto p-6">{children}</main>
    </div>
  );
}

