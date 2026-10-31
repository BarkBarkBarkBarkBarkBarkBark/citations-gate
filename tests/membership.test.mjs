import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyWorkspaceMember, wallSession, wallSettings } from '../lib/wall-session.mjs';

const config = { url: 'https://example.supabase.co', key: 'sb_publishable_test', workspace: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' };
const jwt = payload => `header.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.signature`;
const token = jwt({ sub: 'organizer', role: 'authenticated' });

test('membership is authenticated remotely and scoped via hc_is_member', async () => {
  const calls = [];
  const result = await verifyWorkspaceMember(config, token, async (url, opts) => {
    calls.push({ url, opts }); return Response.json(url.endsWith('/user') ? { id: 'organizer' } : true);
  });
  assert.equal(result, true); assert.equal(calls.length, 2);
  assert.equal(calls[1].opts.headers['Content-Profile'], 'hosaka_citations');
  assert.deepEqual(JSON.parse(calls[1].opts.body), { p_workspace: config.workspace });
});

test('unsigned claim decoding never substitutes for authentication', async () => {
  let calls = 0;
  assert.equal(await verifyWorkspaceMember(config, token, async () => { calls++; return Response.json({}, { status: 401 }); }), false);
  assert.equal(calls, 1);
  assert.equal(await verifyWorkspaceMember(config, jwt({ role: 'service_role' }), async () => { throw new Error('must not call'); }), false);
});

test('nonmember and subject mismatch are rejected', async () => {
  assert.equal(await verifyWorkspaceMember(config, token, async url => Response.json(url.endsWith('/user') ? { id: 'organizer' } : false)), false);
  assert.equal(await verifyWorkspaceMember(config, token, async () => Response.json({ id: 'somebody-else' })), false);
});

test('server-only secret/service-role keys are refused as publishable keys', () => {
  const env = { SUPABASE_URL: config.url, SUPABASE_WORKSPACE_ID: config.workspace };
  assert.throws(() => wallSettings({ ...env, SUPABASE_PUBLISHABLE_KEY: 'sb_secret_x' }), { code: 'publishable_key_required' });
  assert.throws(() => wallSettings({ ...env, SUPABASE_PUBLISHABLE_KEY: jwt({ role: 'service_role' }) }), { code: 'publishable_key_required' });
});

test('missing store has no legacy environment token fallback', () => {
  const env = { SUPABASE_URL: config.url, SUPABASE_WORKSPACE_ID: config.workspace, SUPABASE_PUBLISHABLE_KEY: config.key, SUPABASE_REFRESH_TOKEN: 'old' };
  assert.throws(() => wallSession(env), { code: 'wall_session_store_required' });
});

test('preview cannot use production scope configuration', () => {
  const env = { SUPABASE_URL: config.url, SUPABASE_WORKSPACE_ID: config.workspace, SUPABASE_PUBLISHABLE_KEY: config.key,
    WALL_SESSION_SCOPE: 'citations-gate', WALL_SESSION_ENVIRONMENT: 'production', VERCEL_ENV: 'preview',
    WALL_SESSION_ENCRYPTION_KEY: 'ab'.repeat(32), WALL_SESSION_STORE_SECRET: 'cd'.repeat(32) };
  assert.throws(() => wallSession(env), { code: 'wall_session_store_required' });
});
