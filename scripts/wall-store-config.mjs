// Run privately after loading the three existing SUPABASE_* settings.
// Secrets go only to the ignored .env.local; printed SQL contains only a hash.
import { createHash, randomBytes } from 'node:crypto';
import { appendFile, chmod, lstat } from 'node:fs/promises';
import { wallSettings } from '../lib/wall-session.mjs';

try {
  const environment = process.argv[2];
  if (!['production', 'preview', 'development'].includes(environment)) throw new Error('Specify production, preview, or development.');
  const config = wallSettings();
  if (process.env.WALL_SESSION_ENVIRONMENT && process.env.WALL_SESSION_ENVIRONMENT !== environment) {
    throw new Error('Existing environment differs. Use a separate private config file/process for each environment.');
  }
  try { const st = await lstat('.env.local'); if (!st.isFile() || st.isSymbolicLink()) throw new Error('Private config must be a regular file.'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const values = {
    WALL_SESSION_SCOPE: process.env.WALL_SESSION_SCOPE || 'citations-gate',
    WALL_SESSION_ENVIRONMENT: environment,
    WALL_SESSION_STORE_SECRET: process.env.WALL_SESSION_STORE_SECRET || randomBytes(32).toString('hex'),
    WALL_SESSION_ENCRYPTION_KEY: process.env.WALL_SESSION_ENCRYPTION_KEY || randomBytes(32).toString('hex'),
  };
  if (!/^[a-zA-Z0-9:_-]{1,128}$/.test(values.WALL_SESSION_SCOPE) ||
      !/^[a-f0-9]{64}$/.test(values.WALL_SESSION_STORE_SECRET) ||
      !/^[a-f0-9]{64}$/.test(values.WALL_SESSION_ENCRYPTION_KEY)) throw new Error('Invalid session configuration.');
  await chmod('.env.local', 0o600).catch(error => { if (error.code !== 'ENOENT') throw error; });
  const missing = Object.entries(values).filter(([key]) => !process.env[key]);
  await appendFile('.env.local', '\n' + missing.map(([key, value]) => `${key}=${value}`).join('\n') + '\n', { mode: 0o600 });
  const binding = `${values.WALL_SESSION_SCOPE}:${environment}:${config.url}:${config.workspace}`;
  const scope = `citations-gate:session:v1:${createHash('sha256').update(binding).digest('hex')}`;
  const hash = createHash('sha256').update(values.WALL_SESSION_STORE_SECRET).digest('hex');
  console.log('Session settings saved privately to .env.local. Copy them into the matching Vercel environment privately.');
  console.log('After applying 001_wall_sessions.sql, run this registration SQL as database administrator:');
  console.log(`INSERT INTO citations_gate_private.wall_sessions(scope, secret_hash) VALUES ('${scope}', decode('${hash}', 'hex')) ON CONFLICT (scope) DO NOTHING;`);
} catch {
  console.error('Setup failed. Check explicit environment, existing Supabase settings and private file permissions; do not paste secrets into chat.');
  process.exitCode = 1;
}
