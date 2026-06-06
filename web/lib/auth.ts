/**
 * Auth utilities for VoidAccess frontend.
 * Token stored in sessionStorage (cleared when browser closes).
 * Also mirrored in 'va_token' cookie for middleware protection.
 */

export interface AuthUser {
  email: string
  mustResetPassword: boolean
}

export async function login(
  email: string,
  password: string
): Promise<{ access_token: string; must_reset_password: boolean }> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  })
  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.detail || "Login failed")
  }
  return res.json()
}

export async function resetPassword(
  currentPassword: string,
  newPassword: string,
  confirmPassword: string
): Promise<void> {
  const token = getToken()
  const res = await fetch("/api/auth/reset-password", {
    method: "POST",
    headers: { 
      "Content-Type": "application/json",
      ...(token ? { "Authorization": `Bearer ${token}` } : {})
    },
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
      confirm_password: confirmPassword,
    }),
  })
  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.detail || "Password reset failed")
  }
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  // Primary: sessionStorage (tab-scoped)
  const stored = sessionStorage.getItem("va_token");
  if (stored) return stored;
  // Fallback: cookie (persists across tabs and page reloads)
  const match = document.cookie.match(/(?:^|;\s*)va_token=([^;]+)/);
  const fromCookie = match ? decodeURIComponent(match[1]) : null;
  if (fromCookie) {
    sessionStorage.setItem("va_token", fromCookie);
    return fromCookie;
  }
  return null;
}

export function setToken(token: string): void {
  sessionStorage.setItem("va_token", token)
  // Mirror to cookie for middleware (24hr expiry)
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toUTCString()
  document.cookie = `va_token=${token}; path=/; expires=${expires}; SameSite=Lax`
}

export function clearToken(): void {
  sessionStorage.removeItem("va_token")
  // Clear cookie too via a dummy API call or direct document.cookie
  document.cookie = "va_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"
}
