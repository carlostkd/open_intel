import { NextResponse } from "next/server";
import { getBackendUrl } from "@/lib/backend";

export async function GET() {
  const backendUrl = getBackendUrl();
  try {
    const res = await fetch(`${backendUrl}/health`, {
      cache: "no-store",
    });

    if (!res.ok) {
      return NextResponse.json(
        { status: "error", detail: `Backend returned ${res.status}` },
        { status: res.status }
      );
    }

    const data = await res.json();
    
    // Normalize response for the client
    return NextResponse.json({
      status: data.status === "healthy" ? "ok" : "error",
      tor: data.checks?.tor === "ok",
      database: data.checks?.database === "ok"
    });
  } catch (err) {
    return NextResponse.json(
      { status: "error", detail: err instanceof Error ? err.message : "Backend unreachable" },
      { status: 502 }
    );
  }
}
