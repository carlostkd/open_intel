/**
 * Resolve the VoidAccess FastAPI base URL for Next.js Route Handlers (server-side).
 */
export function getBackendUrl(): string {
  return (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
}
