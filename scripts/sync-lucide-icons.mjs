import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, '..');
const lucideIconsDir = join(repoRoot, 'node_modules/lucide/dist/esm/icons');
const outRoot = join(repoRoot, 'ui/vendor/lucide/esm');
const outIconsDir = join(outRoot, 'icons');

const icons = [
  'app-window',
  'bell',
  'check',
  'chevron-down',
  'circle-check',
  'circle-slash',
  'circle-x',
  'clipboard-copy',
  'clock-alert',
  'copy',
  'eye',
  'eye-off',
  'file-key',
  'gauge',
  'globe',
  'key-round',
  'list',
  'log-in',
  'log-out',
  'pencil',
  'plug',
  'rotate-ccw-key',
  'settings',
  'shield-alert',
  'shield-minus',
  'shield-plus',
  'shield-x',
  'timer',
  'timer-off',
  'trash',
  'unplug',
  'user-round-check',
  'user-round-plus',
  'user-round-x',
  'zap',
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
