import { wallSession } from '../lib/wall-session.mjs';
import { SessionError } from '../lib/session.mjs';

// Credentials arrive only through an anonymous pipe from the hidden prompt.
let input = '';
for await (const chunk of process.stdin) input += chunk;
try {
  const credentials = JSON.parse(input); input = '';
  const { auth, manager } = wallSession();
  const session = await auth.login(credentials.email, credentials.password);
  credentials.password = '';
  await manager.installFreshSession(session);
  console.log('Independent wall session saved. Workspace membership verified. No tokens printed.');
} catch (error) {
  console.error(error instanceof SessionError ? error.code : 'wall_login_failed');
  process.exitCode = 1;
}
