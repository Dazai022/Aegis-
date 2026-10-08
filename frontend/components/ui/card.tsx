import { cn } from "@/lib/utils";
export function Card({ className, children, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-xl border border-slate-800 bg-slate-900 p-6 shadow", className)} {...p}>{children}</div>;
}
export function CardHeader({ className, children, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("mb-4 flex items-center justify-between", className)} {...p}>{children}</div>;
}
export function CardTitle({ className, children, ...p }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn("text-lg font-semibold text-slate-100", className)} {...p}>{children}</h3>;
}

