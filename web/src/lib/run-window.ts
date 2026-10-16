// Per-task run window ("작업 시간대") helpers shared by the task list and detail pages.
// A window is [startMin, endMin) minutes-from-midnight in an IANA timezone; startMin>endMin
// wraps past midnight. The backend validates the timezone and the start!=end rule.

// hmToMin converts a "HH:MM" time input value into minutes from midnight [0,1440).
export function hmToMin(hm: string): number {
  const [h, m] = hm.split(":").map((v) => Number.parseInt(v, 10));
  if (!Number.isFinite(h) || !Number.isFinite(m)) return 0;
  return (((h * 60 + m) % 1440) + 1440) % 1440;
}

// minToHm renders minutes-from-midnight as a "HH:MM" string for a time input.
export function minToHm(min: number): string {
  const h = Math.floor(min / 60);
  const m = min % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

// runWindowTimeZones lists all IANA zones when the browser supports it (the backend
// validates), falling back to a small curated list otherwise.
export function runWindowTimeZones(): string[] {
  try {
    const all = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.("timeZone");
    if (all && all.length > 0) return all;
  } catch {
    // fall through to the curated list
  }
  return [
    "Asia/Seoul",
    "Asia/Tokyo",
    "Asia/Shanghai",
    "UTC",
    "Europe/London",
    "America/New_York",
    "America/Los_Angeles",
  ];
}
