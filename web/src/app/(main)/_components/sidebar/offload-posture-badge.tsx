"use client";

import * as React from "react";

import Link from "next/link";

import { ShieldCheckIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

// OffloadPostureBadge surfaces the execution-plane security posture in the sidebar:
// when the server runs split (ARTEX_AGENT_OFFLOAD != off), it shows a compact badge
// with the mode and the number of connected sandbox Agents, linking to the management
// page. It renders nothing when the split is off/disabled, so single-box users see no
// change. Self-contained: polls the exec-agents endpoint and tolerates a 503 (disabled).
export function OffloadPostureBadge() {
  const t = useTranslations("execAgentsPage");
  const [mode, setMode] = React.useState<"off" | "auto" | "require">("off");
  const [count, setCount] = React.useState(0);

  React.useEffect(() => {
    let alive = true;
    const tick = () => {
      api
        .execAgents()
        .then((r) => {
          if (!alive) return;
          const m = r.offload_mode;
          setMode(m === "auto" || m === "require" ? m : "off");
          setCount(r.agents.length);
        })
        .catch(() => {
          if (alive) setMode("off"); // 503 / disabled → hide
        });
    };
    tick();
    const id = setInterval(tick, 15000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  if (mode === "off") return null;

  const warn = count === 0; // posture declared but no sandbox connected
  return (
    <Link
      prefetch={false}
      href="/system/exec-agents"
      title={t(`offload.${mode}Hint`)}
      className={cn(
        "flex items-center gap-2 rounded-md border px-2 py-1.5 text-xs transition",
        "hover:bg-muted/60 group-data-[collapsible=icon]:justify-center",
        warn
          ? "border-amber-500/60 text-amber-600 dark:text-amber-400"
          : "border-emerald-600/40 text-emerald-700 dark:text-emerald-400",
      )}
    >
      <ShieldCheckIcon className="size-4 shrink-0" />
      <span className="truncate group-data-[collapsible=icon]:hidden">
        {t(`short.${mode}`)} · {t("connectedCount", { count })}
      </span>
    </Link>
  );
}
