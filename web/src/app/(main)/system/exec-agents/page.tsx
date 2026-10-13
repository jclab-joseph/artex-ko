"use client";

import * as React from "react";

import { BoxIcon, DownloadIcon, PlugIcon, RefreshCwIcon, ShieldCheckIcon, XIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { ApiError, api } from "@/lib/api";
import type { ExecAgent, ExecAgentsInfo } from "@/lib/types";

type Mode = "agent-dials-mgmt" | "mgmt-dials-agent";

export default function ExecAgentsPage() {
  const t = useTranslations("execAgentsPage");
  const [info, setInfo] = React.useState<ExecAgentsInfo | null>(null);
  const [disabled, setDisabled] = React.useState(false);
  const [loading, setLoading] = React.useState(true);

  // issue-bundle sheet state
  const [issueOpen, setIssueOpen] = React.useState(false);
  const [mode, setMode] = React.useState<Mode>("agent-dials-mgmt");
  const [address, setAddress] = React.useState("");
  const [agentId, setAgentId] = React.useState("");
  const [issuing, setIssuing] = React.useState(false);

  // dial state (mgmt-dials)
  const [dialId, setDialId] = React.useState("");
  const [dialAddr, setDialAddr] = React.useState("");
  const [dialing, setDialing] = React.useState(false);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .execAgents()
      .then((r) => {
        setInfo(r);
        setDisabled(false);
      })
      .catch((e) => {
        if (e instanceof ApiError && e.status === 503) {
          setDisabled(true);
          setInfo(null);
        } else {
          toast.error(t("loadFailed", { msg: (e as Error).message }));
        }
      })
      .finally(() => setLoading(false));
  }, [t]);

  React.useEffect(() => {
    load();
    const id = setInterval(load, 10000); // Agents connect/drop asynchronously; poll.
    return () => clearInterval(id);
  }, [load]);

  async function issueBundle() {
    if (!address.trim()) {
      toast.error(t("errNoAddress"));
      return;
    }
    setIssuing(true);
    try {
      await api.downloadAgentBundle(mode, address.trim(), agentId.trim() || undefined);
      toast.success(t("bundleDownloaded"));
      setIssueOpen(false);
    } catch (e) {
      toast.error(t("actionFailed", { msg: (e as Error).message }));
    } finally {
      setIssuing(false);
    }
  }

  async function dial() {
    if (!dialId.trim() || !dialAddr.trim()) {
      toast.error(t("errDialFields"));
      return;
    }
    setDialing(true);
    try {
      await api.dialAgent(dialId.trim(), dialAddr.trim());
      toast.success(t("dialOk"));
      setDialId("");
      setDialAddr("");
      load();
    } catch (e) {
      toast.error(t("actionFailed", { msg: (e as Error).message }));
    } finally {
      setDialing(false);
    }
  }

  const offload = info?.offload_mode ?? "off";

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground text-sm">{t("subtitle")}</p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}>
          <RefreshCwIcon className={loading ? "animate-spin" : ""} /> {t("refresh")}
        </Button>
      </div>

      {disabled ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("disabledTitle")}</CardTitle>
            <CardDescription>{t("disabledHint")}</CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <>
          {/* Security posture */}
          <Card>
            <CardHeader>
              <div className="flex flex-wrap items-center gap-3">
                <ShieldCheckIcon className="text-muted-foreground size-5" />
                <CardTitle className="text-base">{t("postureTitle")}</CardTitle>
                <OffloadBadge mode={offload} />
                <span className="text-muted-foreground ml-auto text-sm">
                  {t("connectedCount", { count: info?.agents.length ?? 0 })}
                </span>
              </div>
              <CardDescription className="pt-1">{t(`offload.${normMode(offload)}Hint`)}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
              <div>
                <span className="text-muted-foreground">{t("listenAddr")}: </span>
                <code className="font-mono">{info?.listen_addr ? info.listen_addr : t("listenNone")}</code>
              </div>
            </CardContent>
          </Card>

          {/* Actions */}
          <div className="flex flex-wrap gap-3">
            <Button onClick={() => setIssueOpen(true)}>
              <DownloadIcon /> {t("issueBundle")}
            </Button>
          </div>

          {/* mgmt-dials: connect out to a listening Agent */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("dialTitle")}</CardTitle>
              <CardDescription>{t("dialDesc")}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap items-end gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="dial-id">{t("agentIdLabel")}</Label>
                <Input
                  id="dial-id"
                  className="w-48 font-mono"
                  placeholder="prod-agent-1"
                  value={dialId}
                  onChange={(e) => setDialId(e.target.value)}
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="dial-addr">{t("addressLabel")}</Label>
                <Input
                  id="dial-addr"
                  className="w-64 font-mono"
                  placeholder="10.0.0.5:8791"
                  value={dialAddr}
                  onChange={(e) => setDialAddr(e.target.value)}
                />
              </div>
              <Button variant="outline" onClick={dial} disabled={dialing}>
                <PlugIcon /> {t("dialBtn")}
              </Button>
            </CardContent>
          </Card>

          {/* Connected agents */}
          <div className="flex flex-col gap-3">
            {(info?.agents.length ?? 0) === 0 ? (
              <p className="text-muted-foreground text-sm">{t("noAgents")}</p>
            ) : (
              info?.agents.map((a) => <AgentCard key={a.id} a={a} pins={info.pins} onChanged={load} />)
            )}
          </div>
        </>
      )}

      <Sheet open={issueOpen} onOpenChange={setIssueOpen}>
        <SheetContent className="flex flex-col gap-0 overflow-y-auto">
          <SheetHeader>
            <SheetTitle>{t("issueBundle")}</SheetTitle>
            <SheetDescription>{t("issueBundleDesc")}</SheetDescription>
          </SheetHeader>
          <div className="flex flex-col gap-4 px-4 pb-6">
            <div className="grid gap-2">
              <Label>{t("modeLabel")}</Label>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant={mode === "agent-dials-mgmt" ? "default" : "outline"}
                  onClick={() => setMode("agent-dials-mgmt")}
                >
                  {t("modeAgentDials")}
                </Button>
                <Button
                  size="sm"
                  variant={mode === "mgmt-dials-agent" ? "default" : "outline"}
                  onClick={() => setMode("mgmt-dials-agent")}
                >
                  {t("modeMgmtDials")}
                </Button>
              </div>
              <p className="text-muted-foreground text-xs leading-relaxed">
                {mode === "agent-dials-mgmt" ? t("modeAgentDialsHint") : t("modeMgmtDialsHint")}
              </p>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="b-addr">{t("addressLabel")}</Label>
              <Input
                id="b-addr"
                className="font-mono"
                placeholder={mode === "agent-dials-mgmt" ? "management.example.com:8790" : "0.0.0.0:8791"}
                value={address}
                onChange={(e) => setAddress(e.target.value)}
              />
              <p className="text-muted-foreground text-xs leading-relaxed">
                {mode === "agent-dials-mgmt" ? t("addressAgentDialsHint") : t("addressMgmtDialsHint")}
              </p>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="b-id">{t("agentIdLabel")}</Label>
              <Input
                id="b-id"
                className="font-mono"
                placeholder={t("agentIdOptional")}
                value={agentId}
                onChange={(e) => setAgentId(e.target.value)}
              />
            </div>
            <Button onClick={issueBundle} disabled={issuing}>
              <DownloadIcon /> {t("download")}
            </Button>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

function normMode(m: string): "off" | "auto" | "require" | "pinned" {
  return m === "auto" || m === "require" || m === "pinned" ? m : "off";
}

const offloadVariant = { require: "default", pinned: "default", auto: "secondary", off: "outline" } as const;

function OffloadBadge({ mode }: { mode: string }) {
  const t = useTranslations("execAgentsPage");
  const m = normMode(mode);
  return <Badge variant={offloadVariant[m]}>{t(`offload.${m}`)}</Badge>;
}

function AgentCard({ a, pins, onChanged }: { a: ExecAgent; pins: Record<string, string>; onChanged: () => void }) {
  const t = useTranslations("execAgentsPage");
  const [taskId, setTaskId] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const pinnedTasks = Object.keys(pins)
    .filter((tid) => pins[tid] === a.id)
    .sort();

  async function pin() {
    if (!taskId.trim()) return;
    setBusy(true);
    try {
      await api.pinTaskAgent(a.id, taskId.trim());
      toast.success(t("pinOk"));
      setTaskId("");
      onChanged(); // re-fetch so the new pin shows and survives refresh
    } catch (e) {
      toast.error(t("actionFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }
  async function unpin(tid: string) {
    setBusy(true);
    try {
      await api.unpinTaskAgent(tid);
      toast.success(t("unpinOk"));
      onChanged();
    } catch (e) {
      toast.error(t("actionFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <BoxIcon className="text-muted-foreground size-4" />
          <CardTitle className="font-mono text-base">{a.id}</CardTitle>
          <Badge variant="outline">{a.mode}</Badge>
          {a.remote_addr && <code className="text-muted-foreground font-mono text-xs">{a.remote_addr}</code>}
          <span className="text-muted-foreground ml-auto text-xs">
            {t("connectedAt")}: {new Date(a.connected_at).toLocaleString()}
          </span>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div>
          <div className="text-muted-foreground mb-1 text-xs">{t("toolsCount", { count: a.tools.length })}</div>
          <div className="flex flex-wrap gap-1">
            {a.tools.map((name) => (
              <Badge key={name} variant="secondary" className="font-mono text-[11px]">
                {name}
              </Badge>
            ))}
          </div>
        </div>
        <div className="flex flex-col gap-2 border-t pt-3">
          <span className="text-muted-foreground text-xs">{t("pinLabel")}</span>
          {pinnedTasks.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {pinnedTasks.map((tid) => (
                <Badge key={tid} variant="secondary" className="gap-1 font-mono text-[11px]">
                  {tid}
                  <button
                    type="button"
                    aria-label={t("unpinBtn")}
                    className="hover:text-destructive disabled:opacity-50"
                    disabled={busy}
                    onClick={() => unpin(tid)}
                  >
                    <XIcon className="size-3" />
                  </button>
                </Badge>
              ))}
            </div>
          ) : (
            <span className="text-muted-foreground text-xs italic">{t("noPins")}</span>
          )}
          <div className="flex flex-wrap items-end gap-2">
            <Input
              id={`pin-${a.id}`}
              className="h-8 w-56 font-mono"
              placeholder={t("taskIdPlaceholder")}
              value={taskId}
              onChange={(e) => setTaskId(e.target.value)}
            />
            <Button size="sm" variant="outline" onClick={pin} disabled={busy || !taskId.trim()}>
              {t("pinBtn")}
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
