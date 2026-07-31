import assert from 'node:assert/strict';
import test from 'node:test';
import { anchoredMenuPosition } from '../src/menu-position';

const viewport = { width: 500, height: 400 };
const menu = { width: 220, height: 180 };

test('connection menu opens below and right-aligned when it fits', () => {
  assert.deepEqual(
    anchoredMenuPosition(
      { left: 360, right: 384, top: 40, bottom: 64 },
      menu,
      viewport,
    ),
    { left: 164, top: 68 },
  );
});

test('connection menu flips above rather than clipping the viewport bottom', () => {
  assert.deepEqual(
    anchoredMenuPosition(
      { left: 360, right: 384, top: 300, bottom: 324 },
      menu,
      viewport,
    ),
    { left: 164, top: 116 },
  );
});

test('connection menu clamps every edge in a constrained viewport', () => {
  assert.deepEqual(
    anchoredMenuPosition(
      { left: 2, right: 26, top: 180, bottom: 204 },
      { width: 484, height: 384 },
      viewport,
    ),
    { left: 8, top: 8 },
  );
});
