"use client";

import { useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";

const isInputTarget = (target: EventTarget | null): boolean => {
  if (!target || !(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return tag === "input" || tag === "textarea" || tag === "select";
};

export interface KeyboardShortcut {
  key: string;
  label: string;
  description: string;
}

export const ALL_SHORTCUTS: KeyboardShortcut[] = [
  { key: "N", label: "N", description: "New investigation" },
  { key: "M", label: "M", description: "Go to monitors" },
  { key: "H / ?", label: "H / ?", description: "Show keyboard shortcuts" },
  { key: "Escape", label: "Esc", description: "Close modal or panel" },
  { key: "/", label: "/", description: "Focus search input" },
];

// Graph-specific shortcuts — active when the graph canvas has keyboard focus.
// Actual handling is in GraphVisualization.tsx; this list is for the help modal.
export const GRAPH_SHORTCUTS: KeyboardShortcut[] = [
  { key: "F",      label: "F",   description: "Fit graph to screen (reset camera)" },
  { key: "P",      label: "P",   description: "Pin / unpin hovered node" },
  { key: "H",      label: "H",   description: "Hide hovered node" },
  { key: "R",      label: "R",   description: "Reset all — show all, unpin all, re-layout" },
  { key: "Escape", label: "Esc", description: "Clear selection, show all nodes" },
];

interface UseKeyboardShortcutsOptions {
  onHelp?: () => void;
  onClose?: () => void;
  searchInputSelector?: string;
}

export function useKeyboardShortcuts(options: UseKeyboardShortcutsOptions = {}) {
  const router = useRouter();
  const { onHelp, onClose, searchInputSelector = "[data-search-input]" } = options;

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (isInputTarget(e.target)) return;

      const key = e.key;

      if (key === "n" || key === "N") {
        e.preventDefault();
        router.push("/investigations/new");
        return;
      }

      if (key === "m" || key === "M") {
        e.preventDefault();
        router.push("/monitors");
        return;
      }

      if (key === "h" || key === "?") {
        e.preventDefault();
        onHelp?.();
        return;
      }

      if (key === "Escape") {
        e.preventDefault();
        onClose?.();
        return;
      }

      if (key === "/") {
        e.preventDefault();
        const el = document.querySelector(searchInputSelector) as HTMLInputElement | null;
        el?.focus();
        return;
      }
    },
    [router, onHelp, onClose, searchInputSelector]
  );

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);
}