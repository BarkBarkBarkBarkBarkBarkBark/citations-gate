import { loadWall } from "../../../lib/supabase";
import { SessionError } from "../../../lib/session.mjs";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    return Response.json(await loadWall());
  } catch (error) {
    // Never log provider response bodies, token values, headers, or credentials.
    const code = error instanceof SessionError ? error.code : "wall_read_failed";
    console.warn(JSON.stringify({ event: "wall_unavailable", code }));
    return Response.json({ error: "Citations are temporarily unavailable.", code }, {
      status: 503, headers: { "Cache-Control": "no-store" },
    });
  }
}
