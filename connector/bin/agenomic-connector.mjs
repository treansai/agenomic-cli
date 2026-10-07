#!/usr/bin/env node
// Published packages run the compiled `dist/` (Node does not strip types
// under node_modules); a source checkout runs `src/` with Node's native
// type stripping (Node >= 22.18).
import { existsSync } from 'node:fs';

const entry = existsSync(new URL('../dist/cli.js', import.meta.url)) ? '../dist/cli.js' : '../src/cli.ts';
const { main } = await import(entry);

/**
 * Exits once stdout and stderr are flushed. A write to a pipe the reader
 * is not draining yet completes asynchronously, and process.exit() would
 * drop it: a hook's fail-closed denial must reach the runtime whole.
 */
function exit(code) {
  process.exitCode = code;
  let pending = 2;
  const done = () => {
    if (--pending === 0) process.exit(code);
  };
  // Callbacks run in write order, after every earlier write completed (or failed).
  process.stdout.write('', done);
  process.stderr.write('', done);
}

main(process.argv.slice(2)).then(
  (code) => exit(code ?? 0),
  (error) => {
    process.stderr.write(`agenomic-connector: ${error?.message ?? error}\n`);
    exit(1);
  },
);
