import { supabaseSessionStore } from './supabase-session-store.mjs';
import { createHash } from 'node:crypto';
import { encryptedCodec, sessionManager, SessionError, supabaseAuth } from './session.mjs';

export function wallSettings(env = process.env) {
  let parsed;
  try { parsed = new URL(env.SUPABASE_URL); } catch { throw new SessionError('wall_configuration_required'); }
  const workspace = env.SUPABASE_WORKSPACE_ID ?? '';
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.pathname !== '/' ||
      parsed.search || parsed.hash || !env.SUPABASE_PUBLISHABLE_KEY ||
      !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(workspace)) {
    throw new SessionError('wall_configuration_required');
  }
  const key = env.SUPABASE_PUBLISHABLE_KEY;
  // Legacy service-role keys are JWTs. Modern secret keys must also be refused.
  let role;
  try { role = JSON.parse(Buffer.from(key.split('.')[1], 'base64url').toString()).role; } catch {}
  if (role === 'service_role' || key.startsWith('sb_secret_')) throw new SessionError('publishable_key_required');
  return { url: parsed.origin, key, workspace };
}

export async function verifyWorkspaceMember(config, accessToken, fetchImpl = fetch) {
  let claims;
  try { claims = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64url').toString()); } catch { return false; }
  if (claims.role !== 'authenticated') return false;
  const headers = { apikey: config.key, Authorization: `Bearer ${accessToken}` };
  const options = { redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000) };
  try {
    // Decode is only a role guard. Supabase authenticates the actual token here.
    const userResponse = await fetchImpl(`${config.url}/auth/v1/user`, { ...options, headers });
    if (!userResponse.ok) return false;
    const user = await userResponse.json();
    if (!user.id || user.id !== claims.sub) return false;
    const memberResponse = await fetchImpl(`${config.url}/rest/v1/rpc/hc_is_member`, {
      ...options, method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json', 'Content-Profile': 'hosaka_citations', 'Accept-Profile': 'hosaka_citations' },
      body: JSON.stringify({ p_workspace: config.workspace }),
    });
    return memberResponse.ok && await memberResponse.json() === true;
  } catch { throw new SessionError('membership_verification_unavailable'); }
}

export function wallSession(env = process.env, fetchImpl = fetch) {
  const config = wallSettings(env);
  const scope = env.WALL_SESSION_SCOPE;
  const environment = env.WALL_SESSION_ENVIRONMENT;
  const encryptionKey = env.WALL_SESSION_ENCRYPTION_KEY;
  if (!scope || !['production', 'preview', 'development'].includes(environment) ||
      (env.VERCEL_ENV && env.VERCEL_ENV !== environment) ||
      !encryptionKey || !/^[a-f0-9]{64}$/i.test(encryptionKey) ||
      !env.WALL_SESSION_STORE_SECRET || !/^[a-f0-9]{64}$/.test(env.WALL_SESSION_STORE_SECRET)) {
    throw new SessionError('wall_session_store_required');
  }
  const binding = `${scope}:${environment}:${config.url}:${config.workspace}`;
  const key = `citations-gate:session:v1:${createHash('sha256').update(binding).digest('hex')}`;
  const store = supabaseSessionStore({ url: config.url, publishableKey: config.key, secret: env.WALL_SESSION_STORE_SECRET, fetchImpl });
  const codec = encryptedCodec(Buffer.from(encryptionKey, 'hex'), binding);
  const auth = supabaseAuth({ url: config.url, publishableKey: config.key, fetchImpl });
  const manager = sessionManager({ store, key, codec, auth,
    verifyMembership: token => verifyWorkspaceMember(config, token, fetchImpl) });
  return { manager, auth };
}
