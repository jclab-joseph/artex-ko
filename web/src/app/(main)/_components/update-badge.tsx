"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowUpCircleIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { api } from "@/lib/api";

/**
 * The top bar's "new version available" hint: checked once on full page load, and if there's an update it lights up
 * next to the version number; clicking it jumps straight to the "Version & Updates" card on the system settings page.
 *
 * The backend caches its GitHub query result for 30 minutes, so checking once on every mount here is safe
 * — the unauthenticated GitHub API allows only 60 requests/hour/IP, and without that cache layer, opening a few tabs
 * would exhaust the quota, after which an actual update check would fail.
 *
 * Any query failure is silent: the top bar is not the place to surface errors; the user sees the reason by opening the settings page and clicking "Check for updates".
 */
export function UpdateBadge() {
  const t = useTranslations("header");
  const [latest, setLatest] = React.useState("");

  React.useEffect(() => {
    let alive = true;
    api
      .checkUpdate()
      .then((r) => {
        // has_update already includes the "versions are comparable" check, so dev builds won't light up this hint.
        if (alive && r.has_update && r.latest) setLatest(r.latest.replace(/^v(?=\d)/, ""));
      })
      .catch(() => {
        // Silent: neither being offline nor GitHub rate-limiting should pop an error in the top bar.
      });
    return () => {
      alive = false;
    };
  }, []);

  if (!latest) return null;

  return (
    <Link
      href="/system/settings"
      title={t("updateTitle", { latest })}
      className="inline-flex items-center gap-1.5 rounded-full bg-primary px-2.5 py-1 font-medium text-primary-foreground text-xs transition-opacity hover:opacity-90"
    >
      {/* Breathing dot: the top bar is busy, so plain text is easy to miss; the animation makes it noticeable at a glance. */}
      <span className="relative flex size-1.5">
        <span className="absolute inline-flex size-full animate-ping rounded-full bg-primary-foreground opacity-75" />
        <span className="relative inline-flex size-1.5 rounded-full bg-primary-foreground" />
      </span>
      <ArrowUpCircleIcon className="size-3.5" />
      <span className="hidden sm:inline">{t("updateBadge", { latest })}</span>
      <span className="sm:hidden">{t("updateBadgeShort")}</span>
    </Link>
  );
}
