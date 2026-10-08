import { cn } from "@/lib/utils";
const variants: Record<string, string> = {
  ALLOW: "bg-emerald-900 text-emerald-300 border-emerald-700",
  BLOCK: "bg-red-900 text-red-300 border-red-700",
  REQUIRE_APPROVAL: "bg-amber-900 text-amber-300 border-amber-700",
  LOW: "bg-emerald-900 text-emerald-300",
  MEDIUM: "bg-yellow-900 text-yellow-300",
  HIGH: "bg-orange-900 text-orange-300",
  CRITICAL: "bg-red-900 text-red-300 animate-pulse",
  default: "bg-slate-700 text-slate-300",
};
export function Badge({ label, className }: { label: string; className?: string }) {
  const style = variants[label] || variants.default;
  return <span className={cn("inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium", style, className)}>{label}</span>;
}

