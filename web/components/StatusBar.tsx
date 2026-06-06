"use client";

import { useCallback, useEffect, useState } from "react";

type HealthPayload = {
  status?: string;
  tor?: boolean;
};

export function StatusBar() {
  const [torOk, setTorOk] = useState<boolean | null>(null);
  const [apiOnline, setApiOnline] = useState<boolean | null>(null);

  const poll = useCallback(async () => {
    try {
      const res = await fetch("/api/health", { cache: "no-store" });
      if (!res.ok) {
        setApiOnline(false);
        setTorOk(false);
        return;
      }
      const data = (await res.json()) as HealthPayload;
      setApiOnline(data.status === "ok");
      setTorOk(Boolean(data.tor));
    } catch {
      setApiOnline(false);
      setTorOk(null);
    }
  }, []);

  useEffect(() => {
    void poll();
    const id = window.setInterval(() => void poll(), 30_000);
    return () => window.clearInterval(id);
  }, [poll]);

  return (
    <div className="flex items-center gap-4 font-mono text-[11px] font-medium tracking-tight text-[var(--text-muted)]">
      {/* Tor Status */}
      <div className="flex items-center gap-2">
        <span>TOR</span>
        <span 
          className={`h-1.5 w-1.5 rounded-full transition-colors duration-500 ${
            torOk === null 
              ? "bg-[var(--neutral)]" 
              : torOk 
                ? "bg-[var(--success)] shadow-[0_0_8px_var(--success)] animate-pulse" 
                : "bg-[var(--danger)]"
          }`}
        />
      </div>

      <span className="text-[var(--border-strong)] opacity-30">|</span>

      {/* API Status */}
      <div className="flex items-center gap-2">
        <span>API</span>
        <span 
          className={`h-1.5 w-1.5 rounded-full transition-colors duration-500 ${
            apiOnline === null 
              ? "bg-[var(--neutral)]" 
              : apiOnline 
                ? "bg-[var(--success)] shadow-[0_0_8px_var(--success)]" 
                : "bg-[var(--danger)]"
          }`}
        />
      </div>
    </div>
  );
}
