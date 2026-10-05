#!/usr/bin/env node
// Published packages run the compiled `dist/` (Node does not strip types
// under node_modules); a source checkout runs `src/` with Node's native
// type stripping (Node >= 22.18).
import { existsSync } from 'node:fs';

const entry = existsSync(new URL('../dist/cli.js', import.meta.url)) ? '../dist/cli.js' : '../src/cli.ts';
const { main } = await import(entry);

main(process.argv.slice(2)).then(
  (code) => process.exit(code ?? 0),
  (error) => {
    process.stderr.write(`agenomic-connector: ${error?.message ?? error}\n`);
    process.exit(1);
  },
);
