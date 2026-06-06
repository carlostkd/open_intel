"use client";

import { useState } from "react";
import type { CreateMonitorInput } from "@/types/monitor";

type Props = {
  onSubmit: (input: CreateMonitorInput) => Promise<{ error?: string }>;
};

const INTERVAL_OPTIONS = [
  { label: "24h", value: 24 },
  { label: "48h", value: 48 },
  { label: "72h", value: 72 },
  { label: "Weekly", value: 168 },
];

const ALERT_ON_OPTIONS = [
  { label: "New Results", value: "new_results" },
  { label: "Any Change", value: "any_change" },
  { label: "Any Presence", value: "any_appearance" },
];

export function CreateMonitorForm({ onSubmit }: Props) {
  const [type, setType] = useState<"keyword" | "url">("keyword");
  const [name, setName] = useState("");
  const [query, setQuery] = useState("");
  const [intervalHours, setIntervalHours] = useState(48);
  const [alertOn, setAlertOn] = useState("new_results");

  // Alert channel toggles + values
  const [webhookEnabled, setWebhookEnabled] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [telegramEnabled, setTelegramEnabled] = useState(false);
  const [telegramChatId, setTelegramChatId] = useState("");
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [emailAddr, setEmailAddr] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setFormError("Deployment name is required.");
      return;
    }
    if (!query.trim()) {
      setFormError(`${type === "keyword" ? "Search query" : "Target URL"} is required.`);
      return;
    }

    setSubmitting(true);
    setFormError(null);
    setSuccess(false);

    const input: CreateMonitorInput = {
      name: name.trim(),
      type,
      interval_hours: intervalHours,
      alert_on: alertOn,
      enabled: true,
      webhook_url: webhookEnabled && webhookUrl.trim() ? webhookUrl.trim() : undefined,
      telegram_chat_id:
        telegramEnabled && telegramChatId.trim() ? telegramChatId.trim() : undefined,
      email: emailEnabled && emailAddr.trim() ? emailAddr.trim() : undefined,
    };
    if (type === "keyword") {
      input.query = query.trim();
    } else {
      input.url = query.trim();
    }

    const result = await onSubmit(input);
    setSubmitting(false);

    if (result.error) {
      setFormError(result.error);
    } else {
      setSuccess(true);
      setName("");
      setQuery("");
      setIntervalHours(48);
      setAlertOn("new_results");
      setWebhookEnabled(false);
      setWebhookUrl("");
      setTelegramEnabled(false);
      setTelegramChatId("");
      setEmailEnabled(false);
      setEmailAddr("");
      setTimeout(() => setSuccess(false), 3000);
    }
  };

  return (
    <form
      onSubmit={(e) => void handleSubmit(e)}
      className="p-8 bg-[var(--bg-surface)] border border-[var(--border-dim)] rounded-xl space-y-8"
    >
      <div className="flex items-center justify-between border-b border-[var(--border-dim)] pb-4">
        <h3 className="font-heading text-lg font-bold tracking-tight text-[var(--text-primary)]">Deploy Surveillance Watchpoint</h3>
        <p className="font-mono text-[10px] uppercase tracking-widest text-[var(--accent)]">Protocol: OSINT-MON-01</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="space-y-6">
          {/* Name */}
          <div className="space-y-2">
            <label className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Configuration Alias</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Threat Actor Watch"
              className="w-full h-11 px-4 rounded-md border border-[var(--border-dim)] bg-[var(--bg-void)] text-[13px] text-[var(--text-primary)] placeholder-[var(--text-muted)] opacity-70 focus:opacity-100 transition-all focus:border-[var(--accent-border)] outline-none"
              disabled={submitting}
            />
          </div>

          {/* Type Selection */}
          <div className="space-y-3">
             <label className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Reconnaissance Mode</label>
             <div className="flex p-1 bg-[var(--bg-void)] rounded-lg border border-[var(--border-dim)]">
                {(["keyword", "url"] as const).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => {
                        setType(t);
                        setQuery("");
                    }}
                    className={`flex-1 py-1.5 text-[10px] font-bold uppercase tracking-widest rounded transition-all ${
                        type === t ? "bg-[var(--accent)] text-[var(--text-inverse)] shadow-lg" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                    }`}
                  >
                    {t === "keyword" ? "Analysis" : "Surveillance"}
                  </button>
                ))}
             </div>
          </div>

          {/* Query / URL */}
          <div className="space-y-2">
            <label className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)]">
              {type === "keyword" ? "Search Parameters" : "Target Address"}
            </label>
            <input
              type={type === "url" ? "url" : "text"}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={type === "keyword" ? "Enter search string..." : "https://*.onion/"}
              className="w-full h-11 px-4 rounded-md border border-[var(--border-dim)] bg-[var(--bg-void)] font-mono text-[12px] text-[var(--text-primary)] placeholder-[var(--text-muted)] opacity-70 focus:opacity-100 transition-all focus:border-[var(--accent-border)] outline-none"
              disabled={submitting}
            />
          </div>

          {/* Interval */}
          <div className="space-y-3">
            <label className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Re-Scan Frequency</label>
            <div className="grid grid-cols-4 gap-2">
              {INTERVAL_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setIntervalHours(opt.value)}
                  className={`h-9 rounded border text-[11px] font-bold transition-all ${
                    intervalHours === opt.value
                      ? "border-[var(--accent)] bg-[var(--accent-dim)] text-[var(--accent)]"
                      : "border-[var(--border-dim)] bg-[var(--bg-void)] text-[var(--text-muted)] hover:border-[var(--text-secondary)]"
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          {/* Alert On */}
          <div className="space-y-3">
            <label className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Trigger Condition</label>
            <div className="space-y-2">
              {ALERT_ON_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setAlertOn(opt.value)}
                  className={`w-full flex items-center justify-between px-4 h-10 rounded border text-[11px] font-bold transition-all ${
                    alertOn === opt.value
                      ? "border-[var(--accent-border)] bg-[var(--bg-raised)] text-[var(--text-primary)]"
                      : "border-[var(--border-dim)] bg-[var(--bg-void)] text-[var(--text-muted)] hover:border-[var(--text-secondary)]"
                  }`}
                >
                  <span className="uppercase tracking-widest">{opt.label}</span>
                  {alertOn === opt.value && <span className="h-1.5 w-1.5 rounded-full bg-[var(--accent)] shadow-[0_0_8px_var(--accent)]" />}
                </button>
              ))}
            </div>
          </div>

          {/* Exfiltration Channels */}
          <div className="space-y-3">
            <label className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Notification Exfiltration</label>
            <div className="space-y-3">
              {[
                { id: 'webhook', label: 'Webhook', enabled: webhookEnabled, set: setWebhookEnabled, val: webhookUrl, setVal: setWebhookUrl, placeholder: 'https://...' },
                { id: 'telegram', label: 'Telegram', enabled: telegramEnabled, set: setTelegramEnabled, val: telegramChatId, setVal: setTelegramChatId, placeholder: 'Chat ID' },
                { id: 'email', label: 'Email', enabled: emailEnabled, set: setEmailEnabled, val: emailAddr, setVal: setEmailAddr, placeholder: 'analyst@...' }
              ].map(ch => (
                <div key={ch.id} className="space-y-2">
                  <button
                    type="button"
                    onClick={() => ch.set(!ch.enabled)}
                    className={`w-full flex items-center justify-between px-4 h-9 rounded border text-[11px] font-bold transition-all ${
                      ch.enabled
                        ? "border-[var(--accent-dim)] bg-[var(--accent-dim)] text-[var(--accent)]"
                        : "border-[var(--border-dim)] bg-[var(--bg-void)] text-[var(--text-muted)] hover:border-[var(--text-secondary)]"
                    }`}
                  >
                    <span className="uppercase tracking-widest">{ch.label}</span>
                    <span className="text-[10px] opacity-40">{ch.enabled ? "ACTIVE" : "OFFLINE"}</span>
                  </button>
                  {ch.enabled && (
                    <input
                      type="text"
                      value={ch.val}
                      onChange={(e) => ch.setVal(e.target.value)}
                      placeholder={ch.placeholder}
                      className="w-full h-8 px-3 rounded border border-[var(--border-dim)] bg-[var(--bg-raised)] font-mono text-[10px] text-[var(--text-primary)] placeholder-[var(--text-muted)] transition-all focus:border-[var(--accent-border)] outline-none animate-in slide-in-from-top-1 duration-200"
                    />
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-4 pt-4 border-t border-[var(--border-dim)]">
        {formError && (
          <div className="p-3 bg-[var(--danger-dim)] border border-[var(--danger)]/20 rounded text-[11px] text-[var(--danger)] font-bold uppercase tracking-widest">
            Fault Detected: {formError}
          </div>
        )}
        {success && (
          <div className="p-3 bg-[var(--success-dim)] border border-[var(--success)]/20 rounded text-[11px] text-[var(--success)] font-bold uppercase tracking-widest">
            Deployment Successful: Watchpoint active.
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="w-full h-12 text-[12px] font-bold tracking-[0.2em] uppercase rounded bg-[var(--accent)] text-[var(--text-inverse)] hover:shadow-[0_0_20px_var(--accent-dim)] transition-all flex items-center justify-center disabled:opacity-50"
        >
          {submitting ? "Processing Deployment..." : "Execute Watchpoint Deployment"}
        </button>
      </div>
    </form>
  );
}
