// Server-only building block. Integrate with the existing gate and membership check.
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';

export class SessionError extends Error {
  constructor(code) { super(code); this.name = 'SessionError'; this.code = code; }
}

// Never surface upstream error_description/message: they can contain user data.
const SAFE_AUTH_CODES = new Set([
  'refresh_token_not_found', 'refresh_token_already_used', 'session_not_found',
  'session_expired', 'invalid_credentials', 'user_banned', 'user_not_found',
  'over_request_rate_limit', 'over_email_send_rate_limit', 'unexpected_failure',
]);
export function sanitizedAuthCode(body) {
  return SAFE_AUTH_CODES.has(body?.error_code) ? body.error_code :
    SAFE_AUTH_CODES.has(body?.code) ? body.code : 'auth_request_rejected';
}

export function encryptedCodec(key, scope) {
  if (!Buffer.isBuffer(key) || key.length !== 32 || !scope) throw new SessionError('session_key_invalid');
  const aad = Buffer.from(scope);
  return {
    seal(value) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(aad);
      const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
      return [iv, cipher.getAuthTag(), data].map(x => x.toString('base64url')).join('.');
    },
    open(value) {
      try {
        const [iv, tag, data] = value.split('.').map(x => Buffer.from(x, 'base64url'));
        const cipher = createDecipheriv('aes-256-gcm', key, iv);
        cipher.setAAD(aad); cipher.setAuthTag(tag);
        return JSON.parse(Buffer.concat([cipher.update(data), cipher.final()]).toString());
      } catch { throw new SessionError('session_record_invalid'); }
    },
  };
}

export function supabaseAuth({ url, publishableKey, fetchImpl = fetch }) {
  const origin = new URL(url);
  if (origin.protocol !== 'https:' || origin.username || origin.password || !publishableKey) {
    throw new SessionError('auth_configuration_invalid');
  }
  async function exchange(grant, params) {
    let response;
    try {
      response = await fetchImpl(`${origin.origin}/auth/v1/token?grant_type=${grant}`, {
        method: 'POST', redirect: 'error', cache: 'no-store',
        headers: { apikey: publishableKey, 'Content-Type': 'application/json' },
        body: JSON.stringify(params), signal: AbortSignal.timeout(10000),
      });
    } catch { throw new SessionError('auth_exchange_outcome_unknown'); }
    let body;
    try { body = await response.json(); }
    catch { throw new SessionError('auth_response_invalid'); }
    if (!response.ok) throw new SessionError(sanitizedAuthCode(body));
    if (typeof body.access_token !== 'string' || !body.access_token ||
        typeof body.refresh_token !== 'string' || !body.refresh_token ||
        !Number.isFinite(body.expires_in) || body.expires_in <= 0) {
      throw new SessionError('auth_response_invalid');
    }
    return { access_token: body.access_token, refresh_token: body.refresh_token,
      expires_at: Date.now() + body.expires_in * 1000 };
  }
  return {
    refresh: refresh_token => exchange('refresh_token', { refresh_token }),
    // Invoke only from an owner-authenticated server-side/private terminal flow.
    // Never log arguments, return tokens to the browser, or persist the password.
    login: (email, password) => exchange('password', { email, password }),
  };
}

export function sessionManager({ store, key, codec, auth, verifyMembership,
  now = Date.now, pause = ms => new Promise(resolve => setTimeout(resolve, ms)),
  refreshWindowMs = 60000, inFlightMs = 30000, waitMs = 12000 }) {
  if (!key || typeof verifyMembership !== 'function') throw new SessionError('membership_check_required');
  const encode = record => JSON.stringify(record);
  async function read() {
    const raw = await store.read(key);
    if (raw === null || raw === undefined) throw new SessionError('wall_login_required');
    let record;
    try { record = JSON.parse(raw); } catch { throw new SessionError('session_record_invalid'); }
    if (!record || record.version !== 1 || !['ready', 'refreshing', 'reauth'].includes(record.phase)) {
      throw new SessionError('session_record_invalid');
    }
    return { raw, record };
  }
  async function checked(session) {
    // Must authenticate token with Supabase and check THIS workspace membership.
    if (await verifyMembership(session.access_token) !== true) throw new SessionError('workspace_membership_required');
    return session.access_token;
  }
  return {
    async installFreshSession(session) {
      // Caller must enforce OWNER authorization + CSRF protection; guest gate is insufficient.
      await checked(session);
      if (!session.refresh_token || !Number.isFinite(session.expires_at) || session.expires_at <= now()) {
        throw new SessionError('auth_response_invalid');
      }
      const old = await store.read(key);
      if (old) {
        let previous;
        try { previous = JSON.parse(old); } catch { throw new SessionError('session_record_invalid'); }
        if (previous.phase === 'refreshing' && now() - previous.started < inFlightMs) {
          throw new SessionError('session_refresh_busy');
        }
      }
      const next = encode({ version: 1, phase: 'ready', sealed: codec.seal(session) });
      if (!await store.cas(key, old, next)) throw new SessionError('session_changed_retry_login');
    },
    async accessToken() {
      const deadline = now() + waitMs;
      for (;;) {
        const { raw, record } = await read();
        if (record.phase === 'reauth') throw new SessionError('wall_login_required');
        if (record.phase === 'refreshing') {
          if (now() - record.started >= inFlightMs) {
            // Never take over an uncertain exchange using its old token.
            await store.cas(key, raw, encode({ version: 1, phase: 'reauth', code: 'refresh_interrupted' }));
            throw new SessionError('wall_login_required');
          }
          if (now() >= deadline) throw new SessionError('session_refresh_busy');
          await pause(50); continue;
        }
        const session = codec.open(record.sealed);
        if (!session.access_token || !session.refresh_token || !Number.isFinite(session.expires_at)) {
          throw new SessionError('session_record_invalid');
        }
        if (session.expires_at - now() > refreshWindowMs) return checked(session);
        const marker = encode({ version: 1, phase: 'refreshing', owner: randomUUID(), started: now() });
        if (!await store.cas(key, raw, marker)) continue;
        let renewed;
        try {
          renewed = await auth.refresh(session.refresh_token);
          await checked(renewed);
        } catch (error) {
          const code = error instanceof SessionError ? error.code : 'auth_exchange_failed';
          await store.cas(key, marker, encode({ version: 1, phase: 'reauth', code }));
          throw new SessionError(code);
        }
        if (!await store.cas(key, marker, encode({ version: 1, phase: 'ready', sealed: codec.seal(renewed) }))) {
          throw new SessionError('session_changed_during_refresh');
        }
        return renewed.access_token;
      }
    },
  };
}
