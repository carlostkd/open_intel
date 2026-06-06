"use client";

import { useEffect, useRef } from "react";

interface GraphContextMenuProps {
  x: number;
  y: number;
  nodeId: string;
  isPinned: boolean;
  onFocus: () => void;
  onTogglePin: () => void;
  onHide: () => void;
  onIsolate: () => void;
  onCopy: () => void;
  onClose: () => void;
}

export function GraphContextMenu({
  x,
  y,
  isPinned,
  onFocus,
  onTogglePin,
  onHide,
  onIsolate,
  onCopy,
  onClose,
}: GraphContextMenuProps) {
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [onClose]);

  const items = [
    { label: "Focus node",          icon: "◎", action: onFocus },
    { label: isPinned ? "Unpin" : "Pin", icon: "⊕", action: onTogglePin },
    { label: "Hide node",            icon: "⊘", action: onHide },
    { label: "Show neighbors only",  icon: "⊞", action: onIsolate },
    { label: "Copy value",           icon: "⊡", action: onCopy },
  ];

  return (
    <div
      ref={menuRef}
      className="fixed z-[9999]"
      style={{ left: x, top: y }}
    >
      <div
        className="overflow-hidden rounded-md shadow-2xl"
        style={{
          minWidth: 168,
          border: "1px solid rgba(255,255,255,0.1)",
          background: "rgba(7,11,17,0.97)",
          backdropFilter: "blur(12px)",
        }}
      >
        {items.map((item) => (
          <button
            key={item.label}
            onClick={() => { item.action(); onClose(); }}
            className="flex w-full items-center gap-2.5 px-3 py-[7px] text-left transition-colors hover:bg-white/5"
            style={{
              fontFamily:    "'IBM Plex Mono', monospace",
              fontSize:      11,
              letterSpacing: "0.03em",
              color:         "rgba(200,220,240,0.85)",
            }}
          >
            <span style={{ color: "rgba(200,220,240,0.4)", fontSize: 13, lineHeight: 1 }}>
              {item.icon}
            </span>
            {item.label}
          </button>
        ))}
      </div>
    </div>
  );
}
