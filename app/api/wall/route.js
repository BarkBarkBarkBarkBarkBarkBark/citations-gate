import { loadWall } from "../../../lib/supabase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    return Response.json(await loadWall());
  } catch (error) {
    const message = error instanceof Error ? error.message : "Citations are temporarily unavailable.";
    return Response.json({ error: message }, { status: 503 });
  }
}
