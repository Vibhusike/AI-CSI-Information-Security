import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import process from 'node:process';

const python = process.platform === 'win32' ? '.venv/Scripts/python.exe' : '.venv/bin/python';
if (!existsSync(python)) {
  console.error('Python environment missing. Run: python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt');
  process.exit(1);
}

const children = [
  spawn(python, ['-m', 'uvicorn', 'backend.server:app', '--host', '127.0.0.1', '--port', '8000'], { stdio: 'inherit', env: { ...process.env, PYTHONPATH: 'backend' } }),
  spawn('./node_modules/.bin/vinext', ['dev'], { stdio: 'inherit' }),
];

const stop = () => {
  for (const child of children) child.kill('SIGTERM');
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
for (const child of children) child.on('exit', (code) => {
  if (code && code !== 0) {
    stop();
    process.exitCode = code;
  }
});
