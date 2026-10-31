# citations-gate

Identity gate and read-only wall for **citations.hosaka.xyz**. Guests enter the
party access code. The wall then reads `hosaka_citations` in Supabase. The
party laptop is only a writer: local citations sync up, and this site keeps
rendering when that machine is off.

```
browser ──https──▶ citations.hosaka.xyz (this project, Vercel)
                      │ proxy.js: cookie valid? else /gate
                      ▼ /api/wall
                 Supabase hosaka_citations (publishable key + member session)
                      ▲
                 VirgoZone :8069 on the party laptop (sync only)
```

## Files

- `proxy.js` — Edge proxy. Verifies the HMAC cookie; redirects to `/gate`.
- `lib/gate.js` — Web Crypto HMAC tokens (12 h), constant-time compares.
- `lib/supabase.js` — refreshes a member session and reads the wall.
- `app/gate/page.jsx` — access-code form. `app/api/gate/route.js` — POST sets
  the cookie (303 back to `next`), DELETE clears it, 10 attempts / 5 min / IP.
- `app/wall.jsx` — read-only wall. Polls `/api/wall` every 20s.

## Environment (Production, all `--sensitive`)

| Name | Purpose |
| --- | --- |
| `GATE_SECRET` | signs the cookie |
| `GATE_ACCESS_CODE` | what guests type |
| `SUPABASE_URL` | project URL |
| `SUPABASE_PUBLISHABLE_KEY` | client key; RLS still requires a member JWT |
| `SUPABASE_WORKSPACE_ID` | shared workspace |
| `WALL_SESSION_STORE_SECRET` | random 32-byte scoped storage capability, hex encoded; database stores only its SHA-256 hash |
| `WALL_SESSION_ENCRYPTION_KEY` | independent random 32-byte key, encoded as 64 hex characters |
| `WALL_SESSION_SCOPE` | stable project-specific namespace, e.g. citations-gate |
| `WALL_SESSION_ENVIRONMENT` | production, preview, or development; must match VERCEL_ENV when present |

`CITATIONS_ORIGIN` is unused. Do not point the wall back at a tunnel.

## Private session setup and recovery

Use the existing Supabase PostgreSQL database, not another service or Runtime
Cache. Apply `supabase/migrations/001_wall_sessions.sql` once through a private
database administrator session/SQL editor. It creates an isolated private table
and two restricted RPCs in the already-exposed `hosaka_citations` schema. It
changes no citation records, existing memberships, or existing RLS policies.

The private session table has no grants or policies for anon/authenticated users.
Only two SECURITY DEFINER functions, owned by a dedicated NOLOGIN role, can read
or compare-and-swap a record after checking its high-entropy scoped secret.
That role cannot read other application tables. The RPCs need a publishable key
plus the scoped server-only secret so an expired user session can be refreshed.
Never expose the private schema through the Data API or ship the secret to a browser.

Use separate production/preview sessions; never copy the Pi or Jetson session.
No service-role key is needed or accepted. Preserve your encryption key:
changing it requires a fresh login.

On your own workstation, put the existing SUPABASE_URL,
SUPABASE_PUBLISHABLE_KEY, and SUPABASE_WORKSPACE_ID in ignored `.env.local`.
Remove empty WALL_SESSION_* placeholders before initializing. Run the setup
helper with an explicit target (example: preview):

```bash
node --env-file=.env.local scripts/wall-store-config.mjs preview
```

It generates missing storage/encryption secrets into `.env.local` (mode 0600),
never printing them. It prints registration SQL containing only the scope and
secret hash. Run that SQL privately after the migration. It does not overwrite
an existing scope or erase a session. Copy the four WALL_SESSION_* settings
into the matching Vercel environment privately; do not put them in Git/chat.
Production setup must run with an explicitly separate production configuration.
Preserve the existing private encryption key when recovering an installation.

Create an independent session with:

```bash
npm run wall:login
```

The Python wrapper requires an interactive terminal and prompts for a hidden
password. It passes credentials to Node through a pipe, creates a new Supabase
session, remotely authenticates the user, verifies `hc_is_member` for this
workspace, and saves encrypted tokens. It never writes the password or prints
tokens. No session-administration endpoint is exposed to guests. MFA challenges
are not implemented by this CLI; a challenge requires a separate supported flow.

Production no longer reads `SUPABASE_REFRESH_TOKEN`. Remove that obsolete
setting after verifying the new deployment. Do not reuse it as a fallback.

Prepare a protected preview with its own environment and member session;
verify the live wall and refresh before approving production deployment.
No hosted Supabase verification is implied by unit tests.

## Refresh and diagnostics

An atomic PostgreSQL UPDATE with an expected-record condition coordinates instances before token exchange. A
process that dies mid-refresh cannot safely recover a rotated response:
`refresh_interrupted` requires a fresh private login, not retrying an old token.
Store outages fail closed. The session record has no TTL and tokens are
AES-256-GCM encrypted, bound to project namespace/environment/workspace.

The API logs only `{event: "wall_unavailable", code: ...}` and returns a
sanitized code. Raw provider descriptions, bodies, headers, passwords and tokens
must never be logged. The old deployment only reported HTTP status, so its
historical 400 cannot establish token reuse versus eviction versus revocation.
Safe provider codes such as `refresh_token_not_found` or
`refresh_token_already_used` distinguish future observed failures.

```bash
npm test
npm run build
```

## Known limits

- The hosted wall is read-only. Issuing and resolving still happen on VirgoZone, then sync into Supabase.
- Comments stay on the laptop's SQLite and do not appear here.
- The access code is one shared secret. Hobby plan has no Vercel-native password protection.
- If durable state is lost or a refresh is interrupted, run the private login again. No stale environment-token fallback is attempted.

## Local smoke test

Install dependencies with `npm ci`, set up `.env.local` with a development
session/store, and run `npm run dev`. Requests remain behind the existing party
access gate. Wall reads retain their workspace filters and Supabase RLS checks.

## Validation scope

`npm test` exercises the SQL migration with embedded PostgreSQL (PGlite),
including reruns, private-table denial, wrong/cross-scope credentials, atomic
compare-and-swap, size limits, and owner-role isolation. HTTP adapter tests use
controlled responses. These do not prove live Supabase deployment privileges,
PostgREST RPC exposure or a real organizer login. Those remain preview checks.
