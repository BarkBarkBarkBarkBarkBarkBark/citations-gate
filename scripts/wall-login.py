#!/usr/bin/env python3
"""Private terminal login. Password never appears in argv, output, or files."""
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
if not sys.stdin.isatty():
    raise SystemExit('Run this in your own interactive terminal, not an agent transcript.')
if input('Create an independent wall session in the configured store? Type yes: ').strip() != 'yes':
    raise SystemExit('Cancelled.')
email = input('Organizer email: ').strip()
password = getpass.getpass('Organizer password (hidden): ')
payload = json.dumps({'email': email, 'password': password})
node_args = ['node']
if (root / '.env.local').exists():
    node_args.append('--env-file=.env.local')
result = subprocess.run(node_args + [str(root / 'scripts/wall-login.mjs')], input=payload,
                        text=True, cwd=root, env=os.environ.copy())
raise SystemExit(result.returncode)
