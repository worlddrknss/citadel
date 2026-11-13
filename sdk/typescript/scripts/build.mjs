// Builds the ESM (dist/esm) and CommonJS (dist/cjs) outputs, each with
// .d.ts types, using only the TypeScript compiler.
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const tsc = createRequire(import.meta.url).resolve('typescript/bin/tsc');

rmSync(join(root, 'dist'), { recursive: true, force: true });
for (const project of ['tsconfig.json', 'tsconfig.cjs.json']) {
  execFileSync(process.execPath, [tsc, '-p', join(root, project)], { stdio: 'inherit', cwd: root });
}
// Mark each tree with its module system so Node resolves the .js files right
// regardless of the package's own "type".
mkdirSync(join(root, 'dist/cjs'), { recursive: true });
writeFileSync(join(root, 'dist/cjs/package.json'), JSON.stringify({ type: 'commonjs' }) + '\n');
writeFileSync(join(root, 'dist/esm/package.json'), JSON.stringify({ type: 'module' }) + '\n');
