"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { resetPassword } from "@/lib/auth"

export default function ResetPasswordPage() {
  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const router = useRouter()

  const hasMinLength = newPassword.length >= 8
  const hasLetter = /[a-zA-Z]/.test(newPassword)
  const hasDigit = /[0-9]/.test(newPassword)
  const hasAllRequirements = hasMinLength && hasLetter && hasDigit
  const matchesConfirmation = confirmPassword.length > 0 && newPassword === confirmPassword

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    if (!hasAllRequirements) {
      setError("Password does not meet requirements")
      return
    }

    if (newPassword !== confirmPassword) {
      setError("New password and confirmation do not match")
      return
    }

    setIsLoading(true)
    try {
      await resetPassword(currentPassword, newPassword, confirmPassword)
      router.push("/")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Password reset failed")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[var(--bg-void)] p-4 relative overflow-hidden">
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-[var(--status-warning)] opacity-[0.03] blur-[120px] rounded-full pointer-events-none" />

      <div className="w-full max-w-[400px] relative">
        <div className="animate-in fade-in slide-in-from-bottom-4 duration-700">
          <div className="flex items-center gap-2 mb-8">
            <div className="w-3 h-3 rounded-full bg-[var(--accent)]" />
            <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)] font-syne">
              voidaccess
            </h1>
          </div>
        </div>

        <div className="bg-[var(--bg-surface)] border border-[var(--border-subtle)] rounded-xl p-8 shadow-2xl backdrop-blur-sm animate-in fade-in zoom-in-95 duration-500">
          <div className="mb-6 space-y-2">
            <div className="flex items-center gap-2 text-[var(--status-warning)] font-mono text-[13px]">
              <span>⚠</span>
              <span>Password change required</span>
            </div>
            <p className="text-[var(--text-muted)] text-xs">
              Set a new secure password before continuing.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label
                htmlFor="currentPassword"
                className="font-mono text-[11px] uppercase tracking-wider text-[var(--text-muted)] ml-1"
              >
                Current Password
              </label>
              <input
                id="currentPassword"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
                className="w-full bg-[var(--bg-raised)] border border-[var(--border-subtle)] rounded-lg px-4 py-3 font-mono text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]/50 transition-colors"
              />
            </div>

            <div className="space-y-2">
              <label
                htmlFor="newPassword"
                className="font-mono text-[11px] uppercase tracking-wider text-[var(--text-muted)] ml-1"
              >
                New Password
              </label>
              <input
                id="newPassword"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                className="w-full bg-[var(--bg-raised)] border border-[var(--border-subtle)] rounded-lg px-4 py-3 font-mono text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]/50 transition-colors"
              />
            </div>

            <div className="space-y-2">
              <label
                htmlFor="confirmPassword"
                className="font-mono text-[11px] uppercase tracking-wider text-[var(--text-muted)] ml-1"
              >
                Confirm New Password
              </label>
              <input
                id="confirmPassword"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                className="w-full bg-[var(--bg-raised)] border border-[var(--border-subtle)] rounded-lg px-4 py-3 font-mono text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]/50 transition-colors"
              />
            </div>

            <div className="py-2 space-y-1">
              <p className="text-[var(--text-muted)] text-[10px] font-mono leading-relaxed">
                Requirements:
              </p>
              <ul className="space-y-0.5 text-[10px] font-mono">
                <li className={hasMinLength ? "text-[var(--status-success)]" : "text-[var(--text-muted)]"}>
                  {hasMinLength ? "✓" : "○"} 8+ characters
                </li>
                <li className={hasLetter ? "text-[var(--status-success)]" : "text-[var(--text-muted)]"}>
                  {hasLetter ? "✓" : "○"} at least one letter
                </li>
                <li className={hasDigit ? "text-[var(--status-success)]" : "text-[var(--text-muted)]"}>
                  {hasDigit ? "✓" : "○"} at least one number
                </li>
                <li className={matchesConfirmation ? "text-[var(--status-success)]" : "text-[var(--text-muted)]"}>
                  {matchesConfirmation ? "✓" : "○"} passwords match
                </li>
              </ul>
            </div>

            {error && (
              <div className="font-mono text-[13px] text-[var(--status-danger)] animate-in fade-in slide-in-from-top-2">
                ⚠ {error}
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading || !hasAllRequirements}
              className="w-full bg-[var(--accent)] text-[var(--text-inverse)] font-medium rounded-lg px-4 py-3 flex items-center justify-center gap-2 hover:opacity-90 active:scale-[0.98] transition-all disabled:opacity-50"
            >
              {isLoading ? (
                <div className="w-5 h-5 border-2 border- current border-t-trasparent rounded-full animate-spin" />
              ) : (
                <>
                  Set New Password <span className="text-lg">→</span>
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}