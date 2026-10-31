import { NextResponse } from "next/server";
import { COOKIE_NAME, gateSettings, verifyToken } from "./lib/gate";

// The wall is rendered here from Supabase. VirgoZone is not in the request path.
export const config = {
  matcher: ["/((?!_next/|favicon.ico|gate|api/gate).*)"],
};

export async function proxy(request) {
  const { pathname, search } = request.nextUrl;
  const authorized = await verifyToken(gateSettings().secret, request.cookies.get(COOKIE_NAME)?.value);
  if (!authorized) {
    const login = request.nextUrl.clone();
    login.pathname = "/gate";
    login.search = "";
    login.searchParams.set("next", pathname + search);
    return NextResponse.redirect(login);
  }

  return NextResponse.next();
}
