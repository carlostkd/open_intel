import { NextResponse } from "next/server"
import { getBackendUrl } from "@/lib/backend"

export async function POST(request: Request) {
  const token = request.headers.get("Authorization");
    const body = await request.json()
  const BACKEND_URL = getBackendUrl()

  try {
    const res = await fetch(`${BACKEND_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })

    let data
    const text = await res.text()
    try {
      data = text ? JSON.parse(text) : {}
    } catch {
      // If parsing fails, backend likely returned an HTML error page
      return NextResponse.json(
        { detail: `Backend error (${res.status}): ${text.slice(0, 100)}...` },
        { status: 502 }
      )
    }

    if (!res.ok) {
      return NextResponse.json(data, { status: res.status })
    }

    const response = NextResponse.json(data)

    // Set va_token cookie for middleware
    // Note: In production, use secure: true, httpOnly: true, sameSite: 'strict'
    // For now keeping it simple as per instructions
    response.cookies.set("va_token", data.access_token, {
      path: "/",
      maxAge: 8 * 60 * 60, // 8 hours
      sameSite: "lax",
    })

    return response
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Backend unavailable" },
      { status: 502 }
    )
  }
}