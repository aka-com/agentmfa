import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, '..');
const lucideIconsDir = join(repoRoot, 'node_modules/lucide/dist/esm/icons');
const outRoot = join(repoRoot, 'ui/vendor/lucide/esm');
const outIconsDir = join(outRoot, 'icons');

const icons = [
  'check',
  'copy',
  'eye',
  'eye-off',
  'pencil',
  'rotate-ccw-key',
  'settings',
  'trash',
];

if (!existsSync(lucideIconsDir)) {
  throw new Error('Lucide is not installed. Run `npm install` first.');
}

rmSync(join(repoRoot, 'ui/vendor/lucide'), { recursive: true, force: true });
mkdirSync(outIconsDir, { recursive: true });

for (const icon of icons) {
  const filename = `${icon}.mjs`;
  const source = join(lucideIconsDir, filename);
  const contents = readFileSync(source, 'utf8')
    .replace(/\n\/\/# sourceMappingURL=.*\n?$/, '\n');
  writeFileSync(join(outIconsDir, filename), contents);
}
