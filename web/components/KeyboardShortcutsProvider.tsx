"use client";

import { useState } from "react";
import { useKeyboardShortcuts, ALL_SHORTCUTS } from "@/hooks/useKeyboardShortcuts";

function HelpModal({ onClose }: { onClose: () => void }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-sm rounded-xl border border-[var(--border-dim)] bg-[var(--bg-surface)] p-6 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="font-heading text-[14px] font-bold text-[var(--text-primary)]">
            Keyboard Shortcuts
          </h3>
          <button
            onClick={onClose}
            className="flex h-7 w-7 items-center justify-center rounded border border-[var(--border-dim)] text-[var(--text-muted)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="flex flex-col gap-2">
          {ALL_SHORTCUTS.map((s) => (
            <div key={s.key} className="flex items-center justify-between">
              <span className="font-mono text-[11px] text-[var(--text-muted)]">{s.description}</span>
              <kbd className="rounded border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-2 py-0.5 font-mono text-[10px] font-bold text-[var(--text-secondary)]">
                {s.label}
              </kbd>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ShortcutHintButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="fixed bottom-6 right-6 z-40 flex h-8 w-8 items-center justify-center rounded-full border border-[var(--border-dim)] bg-[var(--bg-surface)] text-[var(--text-muted)] shadow-lg transition-all hover:border-[var(--accent)] hover:text-[var(--accent)]"
      title="Keyboard shortcuts (?)"
      aria-label="Show keyboard shortcuts"
    >
      <span className="font-mono text-[11px] font-bold">?</span>
    </button>
  );
}

interface Props {
  children: React.ReactNode;
}

export function KeyboardShortcutsProvider({ children }: Props) {
  const [showHelp, setShowHelp] = useState(false);

  useKeyboardShortcuts({
    onHelp: () => setShowHelp(true),
    onClose: () => setShowHelp(false),
  });

  return (
    <>
      {children}
      {showHelp && <HelpModal onClose={() => setShowHelp(false)} />}
      <ShortcutHintButton onClick={() => setShowHelp(true)} />
    </>
  );
}