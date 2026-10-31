import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { supabaseSessionStore } from '../lib/supabase-session-store.mjs';

test('Supabase adapter calls scoped RPCs and never puts secrets in URLs', async () => {
  const calls = [];
  const store = supabaseSessionStore({ url: 'https://example.supabase.co', publishableKey: 'public-key', secret: 'ab'.repeat(32),
    fetchImpl: async (url, opts) => { calls.push({ url, opts }); return Response.json(url.endsWith('_read') ? null : true); } });
  assert.equal(await store.read('scope'), null);
  assert.equal(await store.cas('scope', null, 'encrypted'), true);
  assert.ok(!calls[0].url.includes('abab'));
  assert.equal(calls[0].opts.headers['Content-Profile'], 'hosaka_citations');
  assert.equal(JSON.parse(calls[1].opts.body).p_expected, null);
  const bad = supabaseSessionStore({ url: 'https://example.supabase.co', publishableKey: 'public-key', secret: 'ab'.repeat(32), fetchImpl: async () => Response.json({ message: 'secret body' }, { status: 403 }) });
  await assert.rejects(bad.read('scope'), { code: 'session_store_unavailable' });
});

test('real PostgreSQL migration: scoped authorization, CAS, RLS, rerun and role isolation', async () => {
  const db = new PGlite();
  try {
    await db.exec('CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE SCHEMA hosaka_citations;');
    const sql = await readFile(new URL('../supabase/migrations/001_wall_sessions.sql', import.meta.url), 'utf8');
    await db.exec(sql); await db.exec(sql);
    await db.query(`INSERT INTO citations_gate_private.wall_sessions(scope,secret_hash)
      VALUES ('test',sha256(convert_to($1,'UTF8'))),('other',sha256(convert_to($2,'UTF8')))`, ['ab'.repeat(32), 'cd'.repeat(32)]);
    await db.exec('SET ROLE anon;');
    await assert.rejects(db.query('SELECT * FROM citations_gate_private.wall_sessions'), /permission denied/);
    await assert.rejects(db.query('SELECT hosaka_citations.cg_wall_session_read($1,$2)', ['test', '00'.repeat(32)]), /access denied/);
    await assert.rejects(db.query('SELECT hosaka_citations.cg_wall_session_read($1,$2)', ['other', 'ab'.repeat(32)]), /access denied/);
    const query = async (sql, args) => (await db.query(sql, args)).rows[0].value;
    assert.equal(await query('SELECT hosaka_citations.cg_wall_session_read($1,$2) AS value', ['test','ab'.repeat(32)]), null);
    const cas = (old, next) => query('SELECT hosaka_citations.cg_wall_session_cas($1,$2,$3,$4) AS value', ['test','ab'.repeat(32),old,next]);
    assert.equal(await cas(null, 'ciphertext-1'), true);
    assert.equal(await cas(null, 'stale-writer'), false);
    assert.equal(await cas('ciphertext-1', 'ciphertext-2'), true);
    assert.equal(await query('SELECT hosaka_citations.cg_wall_session_read($1,$2) AS value', ['test','ab'.repeat(32)]), 'ciphertext-2');
    await assert.rejects(cas('ciphertext-2', 'x'.repeat(32769)), /invalid session record/);
    // SET ROLE itself checks the original session user (the test harness is an
    // administrator), so inspect the API role's actual membership instead.
    assert.equal((await db.query("SELECT pg_has_role('anon','citations_gate_session_owner','MEMBER') AS member")).rows[0].member, false);
    await db.exec('RESET ROLE; CREATE TABLE public.unrelated_secret(secret text); SET ROLE citations_gate_session_owner;');
    await assert.rejects(db.query('SELECT * FROM public.unrelated_secret'), /permission denied/);
  } finally { await db.close(); }
});
