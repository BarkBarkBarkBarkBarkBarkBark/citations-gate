import test from 'node:test';
import assert from 'node:assert/strict';
import { encryptedCodec, sessionManager, SessionError, supabaseAuth } from '../lib/session.mjs';

function fixture(overrides = {}) {
  const db = new Map();
  const store = { read: async k => db.get(k) ?? null, cas: async (k, old, next) => {
    if ((db.get(k) ?? null) !== old) return false; db.set(k, next); return true;
  } };
  const codec = encryptedCodec(Buffer.alloc(32, 9), 'test-project:workspace:production');
  let calls = 0;
  const auth = { refresh: async token => {
    calls++; assert.equal(token, 'refresh-old');
    await new Promise(resolve => setTimeout(resolve, 15));
    return { access_token: 'access-new', refresh_token: 'refresh-new', expires_at: Date.now() + 3600000 };
  } };
  const opts = { store, codec, key: 'wall', auth, verifyMembership: async () => true, ...overrides };
  const seed = (expires_at = Date.now() + 1000) => db.set('wall', JSON.stringify({ version: 1,
    phase: 'ready', sealed: codec.seal({ access_token: 'access-old', refresh_token: 'refresh-old', expires_at }) }));
  return { db, store, codec, opts, seed, calls: () => calls };
}

test('20 independent instances share one refresh and latest durable session', async () => {
  const f = fixture(); f.seed();
  const result = await Promise.all(Array.from({ length: 20 }, () => sessionManager(f.opts).accessToken()));
  assert.deepEqual(new Set(result), new Set(['access-new'])); assert.equal(f.calls(), 1);
  assert.equal(await sessionManager(f.opts).accessToken(), 'access-new');
  const stored = f.db.get('wall'); assert.ok(!stored.includes('refresh-new')); assert.ok(!stored.includes('access-new'));
});

test('missing durable record fails closed instead of using environment fallback', async () => {
  const f = fixture();
  await assert.rejects(sessionManager(f.opts).accessToken(), { code: 'wall_login_required' });
  assert.equal(f.calls(), 0);
});

test('interrupted refresh never reuses a token or takes over an expired lease', async () => {
  const f = fixture(); f.db.set('wall', JSON.stringify({ version: 1, phase: 'refreshing', started: Date.now() - 60000 }));
  await assert.rejects(sessionManager(f.opts).accessToken(), { code: 'wall_login_required' });
  assert.equal(JSON.parse(f.db.get('wall')).code, 'refresh_interrupted'); assert.equal(f.calls(), 0);
});

test('provider rejection is durable and cannot cause a retry loop', async () => {
  let calls = 0; const f = fixture({ auth: { refresh: async () => { calls++; throw new SessionError('refresh_token_already_used'); } } }); f.seed();
  await assert.rejects(sessionManager(f.opts).accessToken(), { code: 'refresh_token_already_used' });
  await assert.rejects(sessionManager(f.opts).accessToken(), { code: 'wall_login_required' }); assert.equal(calls, 1);
});

test('failed persistence after rotation does not revert to old session', async () => {
  const f = fixture(); f.seed(); const original = f.store.cas;
  f.store.cas = async (k, old, next) => {
    if (old && JSON.parse(old).phase === 'refreshing') throw new SessionError('session_store_unavailable');
    return original(k, old, next);
  };
  await assert.rejects(sessionManager(f.opts).accessToken(), { code: 'session_store_unavailable' });
  assert.equal(JSON.parse(f.db.get('wall')).phase, 'refreshing'); assert.equal(f.calls(), 1);
});

test('membership failure does not install or return another workspace session', async () => {
  const f = fixture({ verifyMembership: async () => false }); const m = sessionManager(f.opts);
  await assert.rejects(m.installFreshSession({ access_token: 'x', refresh_token: 'r', expires_at: Date.now() + 3600000 }), { code: 'workspace_membership_required' });
  assert.equal(f.db.size, 0); f.seed(Date.now() + 3600000);
  await assert.rejects(m.accessToken(), { code: 'workspace_membership_required' });
});

test('new owner login replaces reauth marker and survives a new manager instance', async () => {
  const f = fixture(); f.db.set('wall', JSON.stringify({ version: 1, phase: 'reauth' }));
  await sessionManager(f.opts).installFreshSession({ access_token: 'fresh-access', refresh_token: 'fresh-refresh', expires_at: Date.now() + 3600000 });
  assert.equal(await sessionManager(f.opts).accessToken(), 'fresh-access'); assert.equal(f.calls(), 0);
});

test('fresh login cannot overwrite another instance refreshing', async () => {
  const f = fixture(); f.db.set('wall', JSON.stringify({ version: 1, phase: 'refreshing', started: Date.now() }));
  await assert.rejects(sessionManager(f.opts).installFreshSession({ access_token: 'x', refresh_token: 'r', expires_at: Date.now() + 3600000 }), { code: 'session_refresh_busy' });
});

test('ciphertext rejects tampering and cross-workspace substitution', () => {
  const f = fixture(); const sealed = f.codec.seal({ refresh_token: 'secret' });
  assert.deepEqual(f.codec.open(sealed), { refresh_token: 'secret' });
  assert.throws(() => encryptedCodec(Buffer.alloc(32, 9), 'other-workspace').open(sealed), { code: 'session_record_invalid' });
  assert.throws(() => f.codec.open(sealed.slice(1)), { code: 'session_record_invalid' });
});

test('auth response never includes upstream descriptions or reflected token values', async () => {
  const auth = supabaseAuth({ url: 'https://example.supabase.co', publishableKey: 'public-key', fetchImpl: async () => Response.json({ error_code: 'refresh_token_not_found', error_description: 'secret-token' }, { status: 400 }) });
  await assert.rejects(auth.refresh('secret-token'), e => e.code === 'refresh_token_not_found' && !e.message.includes('secret-token'));
  const unrecognized = supabaseAuth({ url: 'https://example.supabase.co', publishableKey: 'public-key', fetchImpl: async () => Response.json({ code: 'secret-token' }, { status: 400 }) });
  await assert.rejects(unrecognized.refresh('secret-token'), { code: 'auth_request_rejected' });
});
