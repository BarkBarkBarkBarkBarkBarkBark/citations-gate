// Server-only Supabase wall reader; RLS and workspace filters remain mandatory.
import { wallSession } from "./wall-session.mjs";
import { wallSettings as settings } from "./wall-session.mjs";

const SCHEMA = "hosaka_citations";
const SESSION_KEY = "citations-gate:wall-session-recovery-20261031";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let memory = null;
let refreshing = null;

function settings() {
  const url = (process.env.SUPABASE_URL ?? "").replace(/\/+$/, "");
  const key = process.env.SUPABASE_PUBLISHABLE_KEY ?? "";
  const workspace = process.env.SUPABASE_WORKSPACE_ID ?? "";
  if (!url.startsWith("https://") || !key || !UUID.test(workspace)) {
    throw new Error("Supabase wall is not configured.");
  }
  return { url, key, workspace };
}

function claims(token) {
  try {
    const body = token.split(".")[1];
    const json = JSON.parse(Buffer.from(body, "base64url").toString());
    if (!json || json.role !== "authenticated") throw new Error("bad role");
    return json;
  } catch {
    throw new Error("Refusing a non-user Supabase token.");
  }
}

async function readSession() {
  try {
    const cached = await getCache().get(SESSION_KEY);
    if (cached?.refresh_token) return cached;
  } catch {
    // Local `next dev` has no runtime cache.
  }
  if (memory?.refresh_token) return memory;
  return {
    access_token: "",
    refresh_token: process.env.SUPABASE_REFRESH_TOKEN ?? "",
    expires_at: 0,
  };
}

async function writeSession(session) {
  memory = session;
  try {
    await getCache().set(SESSION_KEY, session, { ttl: 60 * 60 * 24 * 30, name: "citations-wall-session" });
  } catch {
    // Local dev keeps the session in memory only.
  }
}

async function refresh(refreshToken) {
  const { url, key } = settings();
  const response = await fetch(`${url}/auth/v1/token?grant_type=refresh_token`, {
    method: "POST",
    headers: { apikey: key, "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Supabase session refresh failed (HTTP ${response.status}).`);
  const body = await response.json();
  if (typeof body.access_token !== "string" || typeof body.refresh_token !== "string") {
    throw new Error("Supabase session refresh returned no user token.");
  }
  claims(body.access_token);
  return {
    access_token: body.access_token,
    refresh_token: body.refresh_token,
    expires_at: Math.floor(Date.now() / 1000) + Number(body.expires_in ?? 3600) - 30,
  };
}

async function accessToken() {
  const session = await readSession();
  if (session.access_token && session.expires_at > Date.now() / 1000 + 60) {
    claims(session.access_token);
    return session.access_token;
  }
  if (!session.refresh_token) throw new Error("Supabase reader session is not configured.");
  const next = await refresh(session.refresh_token);
  await writeSession(next);
  return next.access_token;
}

async function token() {
  if (!refreshing) {
    refreshing = accessToken().finally(() => {
      refreshing = null;
    });
  }
  return refreshing;
}

async function rest(table, query) {
  const { url, key, workspace } = settings();
  const response = await fetch(`${url}/rest/v1/${table}?${query}&workspace_id=eq.${workspace}`, {
    headers: {
      apikey: key,
      Authorization: `Bearer ${await wallSession().manager.accessToken()}`,
      "Accept-Profile": SCHEMA,
    },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Supabase read failed (HTTP ${response.status}).`);
  const rows = await response.json();
  if (!Array.isArray(rows)) throw new Error("Supabase returned an unexpected payload.");
  return rows;
}

export async function loadWall() {
  const [citations, persons, violations] = await Promise.all([
    rest(
      "hc_citations",
      "deleted_at=is.null&select=id,citation_number,person_id,violation_type_id,issued_at,description,status,due_at,issued_by,first_offense&order=issued_at.desc&limit=200",
    ),
    rest("hc_persons", "deleted_at=is.null&select=id,display_name"),
    rest("hc_violation_types", "deleted_at=is.null&select=id,title"),
  ]);
  const names = new Map(persons.map((row) => [row.id, row.display_name]));
  const titles = new Map(violations.map((row) => [row.id, row.title]));
  const now = Date.now();
  const items = citations.map((row) => {
    const due = row.due_at ? Date.parse(row.due_at) : null;
    return {
      id: row.id,
      citation_number: row.citation_number,
      offender: names.get(row.person_id) ?? "Unknown",
      violation: titles.get(row.violation_type_id) ?? "Unknown",
      status: row.status,
      issued_at: row.issued_at,
      due_at: row.due_at,
      issued_by: row.issued_by,
      description: row.description ?? "",
      first_offense: row.first_offense,
      overdue: row.status === "open" && due !== null && due < now,
    };
  });
  return {
    checked_at: new Date().toISOString(),
    counts: {
      open: items.filter((row) => row.status === "open").length,
      resolved: items.filter((row) => row.status === "resolved").length,
      void: items.filter((row) => row.status === "void").length,
      overdue: items.filter((row) => row.overdue).length,
    },
    items,
  };
}
