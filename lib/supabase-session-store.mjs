import { SessionError } from './session.mjs';

// Only two narrowly scoped RPCs, not a service-role/database administrator key.
export function supabaseSessionStore({ url, publishableKey, secret, fetchImpl = fetch }) {
  const origin = new URL(url);
  if (origin.protocol !== 'https:' || origin.username || origin.password ||
      !publishableKey || !/^[a-f0-9]{64}$/.test(secret)) {
    throw new SessionError('session_store_configuration_invalid');
  }
  async function rpc(action, scope, extra = {}) {
    try {
      const response = await fetchImpl(`${origin.origin}/rest/v1/rpc/cg_wall_session_${action}`, {
        method: 'POST', redirect: 'error', cache: 'no-store',
        headers: { apikey: publishableKey, 'Content-Type': 'application/json',
          'Content-Profile': 'hosaka_citations', 'Accept-Profile': 'hosaka_citations' },
        body: JSON.stringify({ p_scope: scope, p_secret: secret, ...extra }),
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) throw new Error();
      return await response.json();
    } catch { throw new SessionError('session_store_unavailable'); }
  }
  return {
    async read(scope) {
      const result = await rpc('read', scope);
      if (result !== null && typeof result !== 'string') throw new SessionError('session_record_invalid');
      return result;
    },
    async cas(scope, expected, next) {
      const result = await rpc('cas', scope, { p_expected: expected, p_next: next });
      if (typeof result !== 'boolean') throw new SessionError('session_record_invalid');
      return result;
    },
  };
}
