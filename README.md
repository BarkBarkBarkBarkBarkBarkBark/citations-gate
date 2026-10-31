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
| `SUPABASE_REFRESH_TOKEN` | refresh token from a **second** organizer login, not the laptop session |

`CITATIONS_ORIGIN` is unused. Do not point the wall back at a tunnel.

```bash
vercel deploy --prod
```

## Known limits

- The hosted wall is read-only. Issuing and resolving still happen on VirgoZone, then sync into Supabase.
- Comments stay on the laptop's SQLite and do not appear here.
- The access code is one shared secret. Hobby plan has no Vercel-native password protection.
- The reader refresh token lives in the runtime cache after the first refresh. If that cache is empty and the env token was already rotated, mint a new login.

## Local smoke test

```bash
npm install && npx next build
GATE_SECRET=x GATE_ACCESS_CODE=pumpkin \
  SUPABASE_URL=https://example.supabase.co \
  SUPABASE_PUBLISHABLE_KEY=sb_publishable_example \
  SUPABASE_WORKSPACE_ID=00000000-0000-4000-8000-000000000000 \
  SUPABASE_REFRESH_TOKEN=refresh \
  npx next start -p 3123
```
# citations-gate
