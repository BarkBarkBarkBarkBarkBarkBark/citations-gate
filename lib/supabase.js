// Server-only Supabase wall reader; RLS and workspace filters remain mandatory.
import { wallSession } from "./wall-session.mjs";
import { wallSettings as settings } from "./wall-session.mjs";

const SCHEMA = "hosaka_citations";

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
