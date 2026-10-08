"use client";
import { useState, useEffect, createContext, useContext } from "react";
import { api, setToken, getToken } from "@/lib/api";

interface AuthCtx { user: any; login: (e: string, p: string) => Promise<void>; logout: () => void; loading: boolean; }
const Ctx = createContext<AuthCtx>({ user: null, login: async () => {}, logout: () => {}, loading: true });
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const t = localStorage.getItem("aegis_token");
    if (t) { setToken(t); api.me().then(setUser).catch(() => setUser(null)).finally(() => setLoading(false)); }
    else setLoading(false);
  }, []);
  const login = async (email: string, password: string) => {
    const { access_token } = await api.login(email, password);
    localStorage.setItem("aegis_token", access_token);
    setToken(access_token);
    const me = await api.me();
    setUser(me);
  };
  const logout = () => { localStorage.removeItem("aegis_token"); setToken(null); setUser(null); };
  return <Ctx.Provider value={{ user, login, logout, loading }}>{children}</Ctx.Provider>;
}

