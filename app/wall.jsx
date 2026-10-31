"use client";

import { useEffect, useState } from "react";

const mono = { fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, letterSpacing: "0.04em", textTransform: "uppercase", color: "#99969e" };

function when(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

export default function Wall() {
  const [wall, setWall] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    async function pull() {
      try {
        const response = await fetch("/api/wall", { cache: "no-store" });
        const body = await response.json();
        if (!response.ok) throw new Error(body.error || "Citations are temporarily unavailable.");
        if (!stop) {
          setWall(body);
          setError("");
        }
      } catch (err) {
        if (!stop) setError(err.message);
      }
    }
    pull();
    const timer = setInterval(pull, 20000);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, []);

  const counts = wall?.counts;
  return (
    <main style={{ width: "min(980px, 100%)", margin: "0 auto", padding: "28px 20px 64px" }}>
      <p style={mono}>hosaka · halloween compliance</p>
      <h1 style={{ margin: "6px 0 8px", fontSize: 28 }}>Wall of shame</h1>
      <p style={{ ...mono, textTransform: "none", letterSpacing: 0 }}>
        {error ? error : counts ? `${counts.open} open · ${counts.overdue} overdue · ${counts.resolved} resolved · ${counts.void} void` : "loading"}
      </p>
      <ul style={{ listStyle: "none", padding: 0, margin: "22px 0 0", display: "grid", gap: 10 }}>
        {(wall?.items ?? []).map((row) => (
          <li key={row.id} style={{ border: "1px solid rgba(255,255,255,0.1)", borderRadius: 10, padding: "12px 14px", background: "rgba(15,15,16,0.94)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "baseline" }}>
              <strong>{row.offender}</strong>
              <span style={{ ...mono, color: row.overdue ? "#f3a7c8" : "#99969e" }}>{row.overdue ? "overdue" : row.status}</span>
            </div>
            <div style={{ marginTop: 4 }}>{row.violation}</div>
            {row.description ? <p style={{ margin: "8px 0 0", color: "#c8c4cc", fontSize: 14 }}>{row.description}</p> : null}
            <p style={{ ...mono, textTransform: "none", letterSpacing: 0, margin: "8px 0 0" }}>
              {row.citation_number} · {when(row.issued_at)}{row.issued_by ? ` · ${row.issued_by}` : ""}
            </p>
          </li>
        ))}
      </ul>
    </main>
  );
}
